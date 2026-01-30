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
  u32 tid = bpf_get_current_pid_tgid();
  u64 *buf_addr = inflight.lookup(&tid);
  if (buf_addr == 0) return 0;
  
  int ret = args->ret;
  if (ret < 5) goto cleanup;
  
  unsigned char data[256];
  if (bpf_probe_read_user(&data, sizeof(data), (void *)*buf_addr) != 0) goto cleanup;
  
  // Check for TLS Handshake (0x16) and SHLO (0x02)
  if (data[0] == 0x16 && data[5] == 0x02) {
    bpf_trace_printk("SERVER HELLO (read)\\n");
    
    // Version from ServerHello message (bytes 9-10)
    unsigned short ver = (data[9] << 8) | data[10];
    
    // sess ID length at byte 43
    unsigned char s_id_len = data[43];
    if (s_id_len > 32) s_id_len = 32;
    
    // cipher suite offset = 44 + sess_id_len
    int cipher_off = (44 + s_id_len) & 0xFF;
    unsigned short cipher = (data[cipher_off] << 8) | data[cipher_off + 1];
    
    // Check for TLS 1.3 by looking at supported_versions extension
    // Extension starts at: 5(record) + 4(handshake) + 2(ver) + 32(random) + 1(sid_len) + sid + 2(cipher) + 1(comp) = 47 + sid_len
    int ext_start = (49 + s_id_len) & 0xFF;
    
    // Simple check: look for 0x002b (supported_versions) in first few positions
    bool is_tls13 = false;
    
    // Check at ext_start (type field)
    unsigned short ext_type = (data[ext_start] << 8) | data[ext_start + 1];
    if (ext_type == 0x002b) {
      int ver_off = (ext_start + 4) & 0xFF;
      ver = (data[ver_off] << 8) | data[ver_off + 1];
      is_tls13 = true;
    }
    
    if (is_tls13) {
      bpf_trace_printk("TLS 1.3: 0x%x\\n", ver);
    } else {
      bpf_trace_printk("TLS 1.2: 0x%x\\n", ver);
    }
    bpf_trace_printk("Cipher: 0x%x\\n", cipher);
  }

cleanup:
  inflight.delete(&tid);
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_recvfrom) {
  u32 tid = bpf_get_current_pid_tgid();
  u64 *buf_addr = inflight.lookup(&tid);
  if (buf_addr == 0) return 0;
  
  int ret = args->ret;
  if (ret < 5) goto cleanup;
  
  unsigned char data[256];
  if (bpf_probe_read_user(&data, sizeof(data), (void *)*buf_addr) != 0) goto cleanup;
  
  // Check for TLS Handshake (0x16) and SHLO (0x02)
  if (data[0] == 0x16 && data[5] == 0x02) {
    bpf_trace_printk("SERVER HELLO (recvfrom)\\n");
    
    // Version from ServerHello message (bytes 9-10)
    unsigned short ver = (data[9] << 8) | data[10];
    
    // sess id length at byte 43
    unsigned char s_id_len = data[43];
    if (s_id_len > 32) s_id_len = 32;
    
    // cipher suite offset = 44 + sess_id_len  
    int cipher_off = (44 + s_id_len) & 0xFF;
    unsigned short cipher = (data[cipher_off] << 8) | data[cipher_off + 1];
    
    // Check for TLS 1.3 by looking at supported_versions extension
    int ext_start = (49 + s_id_len) & 0xFF;
    
    // Simple check: look for 0x002b (supported_versions) in first few positions
    bool is_tls13 = false;
    
    // Check at ext_start (type field)
    unsigned short ext_type = (data[ext_start] << 8) | data[ext_start + 1];
    if (ext_type == 0x002b) {
      int ver_off = (ext_start + 4) & 0xFF;
      ver = (data[ver_off] << 8) | data[ver_off + 1];
      is_tls13 = true;
    }
    
    if (is_tls13) {
      bpf_trace_printk("TLS 1.3: 0x%x\\n", ver);
    } else {
      bpf_trace_printk("TLS 1.2: 0x%x\\n", ver);
    }
    bpf_trace_printk("Cipher: 0x%x\\n", cipher);
  }

cleanup:
  inflight.delete(&tid);
  return 0;
}
