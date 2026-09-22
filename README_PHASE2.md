# StreamTube Phase 2 — Video Processing

Implemented on the uploaded StreamTube project:

- FFmpeg-based server-side H.264/AAC transcoding after upload.
- HLS VOD output (`index.m3u8` + `.ts` segments) under `media/<video-id>/`.
- Video status starts as `processing` and becomes `published` after processing.
- Original uploaded MP4/WebM/MOV/MKV remains available as fallback.
- Watch page uses HLS.js when available and native HLS where supported.
- Correct MIME types and long-lived caching headers for HLS media.

## Important

This is local/server-side video processing, not yet cloud transcoding or CDN delivery. Railway/container filesystems may be ephemeral, so production deployment should move media to persistent object storage (S3/R2/etc.) and run transcoding in a worker/job service.

The PostgreSQL schema from Phase 1 remains included, but the current routes still use the JSON database. No claim is made that PostgreSQL is live until the adapter is connected and tested with a real DATABASE_URL.
