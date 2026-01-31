#include <uapi/linux/ptrace.h>

BPF_HASH(inflight, u32, u64);

TRACEPOINT_PROBE(syscalls, sys_enter_read) {
  u32 tid = bpf_get_current_pid_tgid();
  u64 addr = (u64)args->buf;
  inflight.update(&tid, &addr);
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_recvfrom) {
  u32 tid = bpf_get_current_pid_tgid();
  u64 addr = (u64)args->ubuf;
  inflight.update(&tid, &addr);
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_read) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = pid_tgid;
  u64 *buf_addr = inflight.lookup(&tid);
  if (buf_addr == 0) return 0;
  
  int ret = args->ret;
  if (ret < 5) goto cleanup;
  
  unsigned char data[256];
  if (bpf_probe_read_user(&data, sizeof(data), (void *)*buf_addr) != 0) goto cleanup;
  
  // Case 1: Full TLS record (all-in-one read, like Go crypto/tls)
  // Record header: type(1) + version(2) + length(2) + handshake_type(1)...
  if (data[0] == 0x16 && ret > 5 && data[5] == 0x02) {
    bpf_trace_printk("PID %d: SERVER HELLO (read)\\n", pid);
    
    unsigned short ver = (data[9] << 8) | data[10];
    unsigned char s_id_len = data[43];
    if (s_id_len > 32) s_id_len = 32;
    
    int cipher_off = (44 + s_id_len) & 0xFF;
    unsigned short cipher = (data[cipher_off] << 8) | data[cipher_off + 1];
    
    // TLS 1.3 detection: cipher suites 0x13xx are TLS 1.3 only
    bool is_tls13 = ((cipher >> 8) == 0x13);
    if (is_tls13) {
      ver = 0x0304;  // TLS 1.3
      bpf_trace_printk("PID %d: TLS 1.3 (0x%x)\\n", pid, ver);
    } else {
      bpf_trace_printk("PID %d: TLS 1.2 (0x%x)\\n", pid, ver);
    }
    bpf_trace_printk("PID %d: Cipher 0x%x\\n", pid, cipher);
  }
  // Case 2: ServerHello body only (split read, like OpenSSL)
  // Body starts with: handshake_type(1) + length(3) + version(2) + random(32)...
  else if (data[0] == 0x02 && ret > 40) {
    // Verify it looks like ServerHello: check version field at bytes 4-5
    unsigned short ver = (data[4] << 8) | data[5];
    if (ver == 0x0303 || ver == 0x0302 || ver == 0x0301 || ver == 0x0304) {
      bpf_trace_printk("PID %d: SERVER HELLO (read-body)\\n", pid);
      
      // Session ID length at byte 38 (4 + 2 + 32)
      unsigned char s_id_len = data[38];
      if (s_id_len > 32) s_id_len = 32;
      
      int cipher_off = (39 + s_id_len) & 0xFF;
      unsigned short cipher = (data[cipher_off] << 8) | data[cipher_off + 1];
      
      // TLS 1.3 detection: cipher suites 0x13xx are TLS 1.3 only
      bool is_tls13 = ((cipher >> 8) == 0x13);
      if (is_tls13) {
        ver = 0x0304;  // TLS 1.3
        bpf_trace_printk("PID %d: TLS 1.3 (0x%x)\\n", pid, ver);
      } else {
        bpf_trace_printk("PID %d: TLS 1.2 (0x%x)\\n", pid, ver);
      }
      bpf_trace_printk("PID %d: Cipher 0x%x\\n", pid, cipher);
    }
  }

cleanup:
  inflight.delete(&tid);
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_recvfrom) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = pid_tgid;
  u64 *buf_addr = inflight.lookup(&tid);
  if (buf_addr == 0) return 0;
  
  int ret = args->ret;
  if (ret < 5) goto cleanup;
  
  unsigned char data[256];
  if (bpf_probe_read_user(&data, sizeof(data), (void *)*buf_addr) != 0) goto cleanup;
  
  // Case 1: Full TLS record (all-in-one read)
  if (data[0] == 0x16 && ret > 5 && data[5] == 0x02) {
    bpf_trace_printk("PID %d: SERVER HELLO (recvfrom)\\n", pid);
    
    unsigned short ver = (data[9] << 8) | data[10];
    unsigned char s_id_len = data[43];
    if (s_id_len > 32) s_id_len = 32;
    
    int cipher_off = (44 + s_id_len) & 0xFF;
    unsigned short cipher = (data[cipher_off] << 8) | data[cipher_off + 1];
    
    // TLS 1.3 detection: cipher suites 0x13xx are TLS 1.3 only
    bool is_tls13 = ((cipher >> 8) == 0x13);
    if (is_tls13) {
      ver = 0x0304;  // TLS 1.3
      bpf_trace_printk("PID %d: TLS 1.3 (0x%x)\\n", pid, ver);
    } else {
      bpf_trace_printk("PID %d: TLS 1.2 (0x%x)\\n", pid, ver);
    }
    bpf_trace_printk("PID %d: Cipher 0x%x\\n", pid, cipher);
  }
  // Case 2: ServerHello body only (split read, like OpenSSL/curl)
  else if (data[0] == 0x02 && ret > 40) {
    unsigned short ver = (data[4] << 8) | data[5];
    if (ver == 0x0303 || ver == 0x0302 || ver == 0x0301 || ver == 0x0304) {
      bpf_trace_printk("PID %d: SERVER HELLO (recvfrom-body)\\n", pid);
      
      unsigned char s_id_len = data[38];
      if (s_id_len > 32) s_id_len = 32;
      
      int cipher_off = (39 + s_id_len) & 0xFF;
      unsigned short cipher = (data[cipher_off] << 8) | data[cipher_off + 1];
      
      // TLS 1.3 detection: cipher suites 0x13xx are TLS 1.3 only
      bool is_tls13 = ((cipher >> 8) == 0x13);
      if (is_tls13) {
        ver = 0x0304;  // TLS 1.3
        bpf_trace_printk("PID %d: TLS 1.3 (0x%x)\\n", pid, ver);
      } else {
        bpf_trace_printk("PID %d: TLS 1.2 (0x%x)\\n", pid, ver);
      }
      bpf_trace_printk("PID %d: Cipher 0x%x\\n", pid, cipher);
    }
  }

cleanup:
  inflight.delete(&tid);
  return 0;
}
