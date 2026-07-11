proxy_set_header Host              $host;
proxy_set_header X-Real-IP         $remote_addr;
proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-Host  $host;
proxy_redirect off;
proxy_buffering on;
proxy_buffer_size 8k;
proxy_buffers 8 16k;
# Note: proxy_*_timeout are deliberately NOT set here — they vary per
# location (inventory ingest needs 120s; general API is fine at 60s).
# Each location block sets its own, or relies on nginx defaults.
