// path: src/nfq/nfq.go
package nfq

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/daniellavrushin/b4sni/config"
	"github.com/daniellavrushin/b4sni/log"
	"github.com/daniellavrushin/b4sni/mangle"
	"github.com/daniellavrushin/b4sni/sni"
	"github.com/florianl/go-nfqueue"
	"golang.org/x/sys/unix"
)

type flowState struct {
	buf  []byte
	last time.Time
}

type Worker struct {
	cfg     *config.Config
	qnum    uint16
	ctx     context.Context
	cancel  context.CancelFunc
	q       *nfqueue.Nfqueue
	wg      sync.WaitGroup
	mu      sync.Mutex
	flows   map[string]*flowState
	ttl     time.Duration
	limit   int
	matcher *sni.SuffixSet
}

func (w *Worker) Start() error {
	log.Infof("Starting NFQueue worker on queue %d", w.qnum)

	flags := nfqueue.NfQaCfgFlagFailOpen
	if w.cfg.UseGSO {
		flags |= nfqueue.NfQaCfgFlagGSO
	}
	if w.cfg.UseConntrack {
		flags |= nfqueue.NfQaCfgFlagConntrack
	}

	c := nfqueue.Config{
		NfQueue:      w.qnum,
		MaxPacketLen: 0xffff,
		MaxQueueLen:  4096,
		Copymode:     nfqueue.NfQnlCopyPacket,
		Flags:        uint32(flags),
		AfFamily:     unix.AF_UNSPEC,
	}
	q, err := nfqueue.Open(&c)
	if err != nil {
		return err
	}
	w.q = q
	w.wg.Add(1)
	go w.gc()
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		pid := os.Getpid()
		log.Infof("NFQ bound pid=%d queue=%d", pid, w.qnum)
		_ = q.RegisterWithErrorFunc(w.ctx, func(a nfqueue.Attribute) int {
			if a.PacketID == nil {
				return 0
			}
			id := *a.PacketID
			if a.Payload == nil || len(*a.Payload) == 0 {
				_ = q.SetVerdict(id, nfqueue.NfAccept)
				return 0
			}
			raw := *a.Payload

			result, err := mangle.ProcessPacket(w.cfg, raw)
			if err != nil {
				log.Debugf("mangle error: %v", err)
			}

			switch result.Verdict {
			case mangle.VerdictDrop:
				_ = q.SetVerdict(id, nfqueue.NfDrop)
				return 0
			case mangle.VerdictModify:
				if len(result.Modified) > 0 {
					_ = q.SetVerdictWithMark(id, nfqueue.NfRepeat, int(w.cfg.Mark))
					raw = result.Modified
				} else {
					_ = q.SetVerdict(id, nfqueue.NfAccept)
				}
			default:
				_ = q.SetVerdict(id, nfqueue.NfAccept)
			}

			v := raw[0] >> 4
			if v != 4 && v != 6 {
				return 0
			}

			if v == 4 && len(raw) < 20 {
				return 0
			}
			if v == 6 && len(raw) < 40 {
				return 0
			}

			var proto uint8
			var src, dst net.IP
			var ihl int

			if v == 4 {
				ihl = int(raw[0]&0x0f) * 4
				if len(raw) < ihl {
					return 0
				}
				proto = raw[9]
				src = net.IP(raw[12:16])
				dst = net.IP(raw[16:20])
			} else {
				ihl = 40
				proto = raw[6]
				src = net.IP(raw[8:24])
				dst = net.IP(raw[24:40])
			}

			if proto == 6 && len(raw) >= ihl+20 {
				tcp := raw[ihl:]
				if len(tcp) < 20 {
					return 0
				}
				datOff := int((tcp[12]>>4)&0x0f) * 4
				if len(tcp) < datOff {
					return 0
				}
				payload := tcp[datOff:]
				sport := binary.BigEndian.Uint16(tcp[0:2])
				dport := binary.BigEndian.Uint16(tcp[2:4])
				if dport == 443 && len(payload) > 0 {
					k := fmt.Sprintf("%s:%d>%s:%d", src.String(), sport, dst.String(), dport)
					host, ok := w.feed(k, payload)
					if ok && host != "" {
						log.Infof("TCP: %s %s:%d -> %s:%d", host, src.String(), sport, dst.String(), dport)
					}
				}
			} else if proto == 17 && len(raw) >= ihl+8 {
				udp := raw[ihl:]
				if len(udp) >= 8 {
					payload := udp[8:]
					sport := binary.BigEndian.Uint16(udp[0:2])
					dport := binary.BigEndian.Uint16(udp[2:4])
					if dport == 443 {
						if host, ok := sni.ParseQUICClientHelloSNI(payload); ok && host != "" {
							log.Infof("QUIC: %s %s:%d -> %s:%d", host, src.String(), sport, dst.String(), dport)
						}
					}
				}
			}

			return 0
		}, func(err error) int {
			log.Errorf("NFQ error: %v", err)
			return 0
		})
		<-w.ctx.Done()
	}()
	return nil
}

func (w *Worker) feed(key string, chunk []byte) (string, bool) {
	w.mu.Lock()
	st := w.flows[key]
	if st == nil {
		st = &flowState{buf: nil, last: time.Now()}
		w.flows[key] = st
	}
	if len(st.buf) < w.limit {
		need := w.limit - len(st.buf)
		if len(chunk) < need {
			st.buf = append(st.buf, chunk...)
		} else {
			st.buf = append(st.buf, chunk[:need]...)
		}
	}
	st.last = time.Now()
	buf := append([]byte(nil), st.buf...)
	w.mu.Unlock()
	host, ok := sni.ParseTLSClientHelloSNI(buf)
	if ok && host != "" {
		w.mu.Lock()
		delete(w.flows, key)
		w.mu.Unlock()
		return host, true
	}
	return "", false
}

func (w *Worker) gc() {
	defer w.wg.Done()
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-w.ctx.Done():
			return
		case now := <-t.C:
			w.mu.Lock()
			for k, st := range w.flows {
				if now.Sub(st.last) > w.ttl {
					delete(w.flows, k)
				}
			}
			w.mu.Unlock()
		}
	}
}

func (w *Worker) Stop() {
	w.cancel()
	if w.q != nil {
		_ = w.q.Close()
	}
	w.wg.Wait()
}
