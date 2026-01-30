#include <uapi/linux/ptrace.h>

BPF_HASH(inflight_read, u32, u64);

TRACEPOINT_PROBE(syscalls, sys_enter_read) {
  u32 tid = bpf_get_current_pid_tgid();
  u64 addr = (u64)args->buf;
  inflight_read.update(&tid, &addr);
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_read) {
  u32 tid = bpf_get_current_pid_tgid();
  u64 *buf_addr = inflight_read.lookup(&tid);

  if (buf_addr == 0) return 0;

  int ret = args->ret;
  if (ret < 5) goto cleanup;

  unsigned char data[256];
  if (bpf_probe_read_user(&data, sizeof(data), (void *)*buf_addr) == 0) {
    if (data[0] == 0x16 && data[5] == 0x02) { // Is TLSHANDSHAKE + Is SERVERHELLO
      //bpf_trace_printk("SERVER HELLO\\n");
      unsigned short negotiated_version = (data[9] << 8) | data[10];
      bool is_tls13 = false;

      unsigned char s_id_len = data[43]; // Session id is used to get offset to extensions
      if (s_id_len > 32) s_id_len = 32;

      int cipher_offset = 44 + s_id_len;
      unsigned short cipher_id;
      if (cipher_offset + 2 <= 256) {
        cipher_id = (data[cipher_offset] << 8) | data[cipher_offset + 1];
      }

      // Skip Record(5) + Handshake(4) + Version(2) + Random(32) + S_ID_Len(1) + S_ID(L) + Cipher(2) + Compression(1)
      // (This works for tls13 but tls12?)
      int ext_offset = 47 + s_id_len;

      unsigned short ext_total_len = (data[ext_offset] << 8) | data[ext_offset + 1];
      int cur_ext = ext_offset + 2;

      unsigned char *ptr = data + ext_offset + 2;
      unsigned char *data_end = data + 256;
      #define MAX_EXTENSIONS 8
      // ebpf does not like dynamic unbounder loops :(  SAD!
      // For unroll to work max_ext needs to be constant. It "unrolls" at comp time.
      // #pragma unroll unrolls this loop into MAX_EXTENSION iterations.
      #pragma unroll 
      for (int i = 0; i < MAX_EXTENSIONS; i++) { 
        if (ptr + 4 > data_end) break;

        unsigned short type = (ptr[0] << 8) | ptr[1];
        unsigned short len = (ptr[2] << 8) | ptr[3];

        if (type == 0x002b) { // supported_versions codepoint is 43 (0x002b) https://datatracker.ietf.org/doc/html/rfc8446#section-4.2
          if (ptr + 6 <= data_end) {
            negotiated_version = (ptr[4] << 8) | ptr[5];
            is_tls13 = true;
          }
          break;
        }

        if (len > 128) break;
        ptr += 4 + len;
      }
      if (is_tls13) {
        bpf_trace_printk("Negotiated TLS Version: TLS1.3 (0x%x)\\n", negotiated_version);
      } else {
        bpf_trace_printk("Negotiated TLS Version: TLS1.2 (0x%x)\\n", negotiated_version);
      }
      bpf_trace_printk("Selected Cipher ID: 0x%x\\n", cipher_id);
    }
  }

cleanup:
  inflight_read.delete(&tid);
  return 0;
}
