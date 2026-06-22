xfinject payload directory

Runtime payload SO directory:
  /product/lib64/xfinject/

Runtime config directory:
  /product/etc/xfinject/

Built-in payloads:
  - libjnilog.so: jnitrace:Arsylk/jnilog

Usage notes:
  - Prefer stable payload IDs from /product/etc/xfinject/payloads.json.
  - Custom debug payloads may be placed under /data/local/tmp/ and injected by absolute path when allow_direct_paths is enabled.
  - ROM-shipped common payloads should be installed under /product/lib64/xfinject/ and registered in payloads.json.
