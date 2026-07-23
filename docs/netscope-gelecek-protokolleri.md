# Netscope Gelecek Protokol Yol Haritası 🛣️

> Bu belge, Netscope sistemine eklenmesi önerilen **350 adet** modern, yeni nesil ve stratejik öneme sahip protokolü listeler.
> Her protokol senior-seviye mühendislik değerlendirmesinden geçirilmiş; gerçek dünya kullanımı, pazar payı, teknik karmaşıklık ve Netscope'un
> stratejik yönü göz önüne alınarak seçilmiştir.
>
> **Tarih:** 2026-07-23
> **Toplam Önerilen Protokol:** 350
> **Kategori Sayısı:** 5

---

## İçindekiler

1. [Modern ve Tescilli Bulut / RPC Protokolleri](#1-modern-ve-tescilli-bulut--rpc-protokolleri) — 85 adet
2. [Modern Oyun ve Gerçek Zamanlı Eğlence Protokolleri](#2-modern-oyun-ve-gerçek-zamanlı-eğlence-protokolleri) — 70 adet
3. [Yapay Zeka ve Büyük Dil Modeli (LLM) Trafik Protokolleri](#3-yapay-zeka-ve-büyük-dil-modeli-llm-trafik-protokolleri) — 65 adet
4. [Gelişmiş IoT ve Endüstriyel Yapay Zeka Protokolleri](#4-gelişmiş-iot-ve-endüstriyel-yapay-zeka-protokolleri) — 65 adet
5. [Gelişmiş Şifreleme ve Kuantum Sonrası (Post-Quantum) Protokoller](#5-gelişmiş-şifreleme-ve-kuantum-sonrası-post-quantum-protokoller) — 65 adet

---

## 1. Modern ve Tescilli Bulut / RPC Protokolleri

> **Toplam:** 85 protokol | **Odak:** Cloud-native, microservice mesh, proprietary RPC, edge compute, serverless

### 1.1 Google Internal / Borg / Stubby Ekosistemi (12 adet)

| | # | Protokol | Açıklama |
|---|---|---|---|
| [ ] | 1 | `stubby` | Google'ın internal RPC framework'ü, gRPC'nin atası |
| [ ] | 2 | `stubby_v3` | Stubby v3 wire format — Google Cloud internal |
| [ ] | 3 | `borg_task` | Borg cluster manager task iletişim protokolü |
| [ ] | 4 | `borgmaster_api` | Borg master scheduling API iletişimi |
| [ ] | 5 | `boq_metro` | Google Boq (Book of Queries) metro batching protokolü |
| [ ] | 6 | `loom` | Google Loom — cross-datacenter tenant isolation protocol |
| [ ] | 7 | `balsa` | Google Balsa — low-latency RPC for search backend |
| [ ] | 8 | `aquila` | Google Aquila — in-memory storage rpc |
| [ ] | 9 | `tango_core` | Google Tango core messaging (internal pub/sub kernel) |
| [ ] | 10 | `gmock_rpc` | Google mock RPC test framework wire format |
| [ ] | 11 | `gws_http` | Google Web Server internal HTTP extensions |
| [ ] | 12 | `cfs_rpc` | Google Colossus File System RPC |

### 1.2 Amazon Internal / AWS Ekosistemi (10 adet)

| | # | Protokol | Açıklama |
|---|---|---|---|
| [ ] | 13 | `aws_sigv4` | AWS Signature v4 signing protocol extension |
| [ ] | 14 | `s3_select_rpc` | Amazon S3 Select internal RPC |
| [ ] | 15 | `dynamodb_internal` | DynamoDB partition-level internal gossip |
| [ ] | 16 | `lambda_invoke` | AWS Lambda invoke wire protocol (internal) |
| [ ] | 17 | `aws_tls` | AWS TLS termination internal next-hop proto |
| [ ] | 18 | `nitro_enclave` | AWS Nitro Enclave vsock protocol |
| [ ] | 19 | `aws_kms_rpc` | AWS KMS internal HSM-to-frontend RPC |
| [ ] | 20 | `ec2_nitro_vsock` | EC2 Nitro hypervisor vsock extensions |
| [ ] | 21 | `aws_sqs_internal` | SQS internal broker replication log proto |
| [ ] | 22 | `aws_aurora_storage` | Aurora storage layer RPC (log-based replication) |

### 1.3 Microsoft Azure / Internal (6 adet)

| | # | Protokol | Açıklama |
|---|---|---|---|
| [ ] | 23 | `azure_fabric_rpc` | Azure Service Fabric internal RPC |
| [ ] | 24 | `azure_hcsshim` | Azure Host Compute Service shim protocol |
| [ ] | 25 | `azure_rdma_smb` | Azure RDMA-capable SMB direct |
| [ ] | 26 | `azure_sdn_policy` | Azure SDN policy distribution protocol |
| [ ] | 27 | `cosmos_db_transport` | Cosmos DB internal transport (not client-facing) |
| [ ] | 28 | `azure_akv_rpc` | Azure Key Vault internal HSM RPC |

### 1.4 Modern RPC Framework'leri (12 adet)

| | # | Protokol | Açıklama |
|---|---|---|---|
| [ ] | 29 | `connect_rpc` | Buf Connect protocol — gRPC-compatible HTTP/1.1 + HTTP/2 |
| [ ] | 30 | `twirp_v7` | Twirp (Twitch RPC) Protobuf over HTTP/1.1 v7 |
| [ ] | 31 | `twirp_v8` | Twirp v8 with streaming support |
| [ ] | 32 | `rpcx` | rpcx — Go microservice RPC framework wire format |
| [ ] | 33 | `tars_jce` | Tencent Tars JCE encoding protocol |
| [ ] | 34 | `tars_wup` | Tencent Tars WUP (UniPacket) protocol |
| [ ] | 35 | `dubbo3_triple` | Apache Dubbo3 Triple protocol (gRPC-compatible) |
| [ ] | 36 | `brpc_thrift` | Baidu brpc Thrift protocol |
| [ ] | 37 | `brpc_nshead` | Baidu brpc nshead protocol |
| [ ] | 38 | `motan2` | Weibo Motan2 RPC binary protocol |
| [ ] | 39 | `sofa_rpc_bolt` | Ant Group SOFARPC Bolt protocol |
| [ ] | 40 | `kitex_ttheader` | ByteDance Kitex TTHeader protocol |

### 1.5 Service Mesh / Sidecar (10 adet)

| | # | Protokol | Açıklama |
|---|---|---|---|
| [ ] | 41 | `envoy_xds_v3` | Envoy xDS v3 discovery protocol (LDS/RDS/CDS/EDS) |
| [ ] | 42 | `envoy_hcm` | Envoy HTTP connection manager internal |
| [ ] | 43 | `istio_mcp` | Istio Mesh Configuration Protocol |
| [ ] | 44 | `linkerd_h2` | Linkerd2-proxy internal HTTP/2 mesh proto |
| [ ] | 45 | `linkerd_dst` | Linkerd destination service discovery |
| [ ] | 46 | `consul_connect_mesh` | Consul Connect sidecar mesh wire |
| [ ] | 47 | `kuma_dp` | Kuma (Kong Mesh) data plane protocol |
| [ ] | 48 | `traefik_hub` | Traefik Hub mesh control plane |
| [ ] | 49 | `cilium_hubble` | Cilium Hubble observability eBPF export |
| [ ] | 50 | `dapr_sidecar` | Dapr sidecar-to-sidecar internal gRPC |

### 1.6 Cloud-Native Streaming & Messaging (10 adet)

| | # | Protokol | Açıklama |
|---|---|---|---|
| [ ] | 51 | `redpanda_rpc` | Redpanda (Kafka-compatible) internal RPC |
| [ ] | 52 | `pulsar_bookkeeper` | Apache Pulsar BookKeeper replication protocol |
| [ ] | 53 | `pulsar_binary_v2` | Apache Pulsar binary protocol v2 |
| [ ] | 54 | `nats_leaf` | NATS leaf node hub-spoke proto |
| [ ] | 55 | `nats_jetstream_internal` | JetStream internal stream replication |
| [ ] | 56 | `rabbitmq_stream` | RabbitMQ stream protocol (new-gen) |
| [ ] | 57 | `amqp_1_0_management` | AMQP 1.0 management extension |
| [ ] | 58 | `solace_smf` | Solace SMF (SEMP over Message Format) |
| [ ] | 59 | `kafka_kraft` | Apache Kafka KRaft consensus metadata proto |
| [ ] | 60 | `kafka_zk_migration` | Kafka ZooKeeper-to-KRaft migration bridge |

### 1.7 Edge / CDN / Serverless (12 adet)

| | # | Protokol | Açıklama |
|---|---|---|---|
| [ ] | 61 | `cloudflare_warp` | Cloudflare WARP tunneling protocol (WireGuard fork) |
| [ ] | 62 | `cloudflare_quiche` | Cloudflare QUICHE internal extensions |
| [ ] | 63 | `fastly_edge_rpc` | Fastly Compute@Edge internal edge RPC |
| [ ] | 64 | `fly_io_proxy` | Fly.io Fly Proxy TCP routing protocol |
| [ ] | 65 | `vercel_edge_runtime` | Vercel Edge Runtime sandbox IPC |
| [ ] | 66 | `deno_deploy_isolate` | Deno Deploy isolate-to-isolate message passing |
| [ ] | 67 | `cloudflare_durable_object` | Cloudflare Durable Object global coordination |
| [ ] | 68 | `wasmtime_wasi_nn` | Wasmtime WASI-NN inference RPC |
| [ ] | 69 | `wagi` | WebAssembly Gateway Interface protocol |
| [ ] | 70 | `spin_trigger_http` | Fermyon Spin trigger-to-wasm ABI |
| [ ] | 71 | `akamai_ghost_rpc` | Akamai Ghost internal edge server RPC |
| [ ] | 72 | `lambda@edge_rpc` | CloudFront Lambda@Edge internal invoke |

### 1.8 Cloud DB Internal Protocols (13 adet)

| | # | Protokol | Açıklama |
|---|---|---|---|
| [ ] | 73 | `spanner_true_time` | Google Spanner TrueTime API protocol |
| [ ] | 74 | `spanner_split_mgr` | Spanner split management RPC |
| [ ] | 75 | `cassandra_gossip_v4` | Apache Cassandra internode gossip v4 |
| [ ] | 76 | `cassandra_murmur3_partition` | Cassandra consistent hash-aware proxy layer |
| [ ] | 77 | `cockroachdb_kv_rpc` | CockroachDB KV layer RPC |
| [ ] | 78 | `cockroachdb_dist_sql` | CockroachDB distributed SQL data exchange |
| [ ] | 79 | `yugabyte_docdb_rpc` | YugabyteDB DocDB tablet RPC |
| [ ] | 80 | `foundationdb_native` | Apple FoundationDB native wire protocol |
| [ ] | 81 | `tikv_raft` | TiKV Raft consensus transport |
| [ ] | 82 | `tikv_titan` | TiKV Titan blob storage layer |
| [ ] | 83 | `vitess_vtgate` | Vitess VtGate query routing internal |
| [ ] | 84 | `planetscale_db_rpc` | PlanetScale database RPC (Vitess-based) |
| [ ] | 85 | `scylladb_rpc` | ScyllaDB internode RPC (Seastar-based) |

---

## 2. Modern Oyun ve Gerçek Zamanlı Eğlence Protokolleri

> **Toplam:** 70 protokol | **Odak:** Real-time multiplayer, game engine networking, voice chat, metaverse

### 2.1 Modern Oyun Motoru Networking (15 adet)

| | # | Protokol | Açıklama |
|---|---|---|---|
| [ ] | 86 | `unreal_iris` | Unreal Engine 5 Iris replication system |
| [ ] | 87 | `unreal_iris_fast_array` | Unreal Engine Iris fast array serializer |
| [ ] | 88 | `unreal_replication_graph` | Unreal Engine ReplicationGraph node protocol |
| [ ] | 89 | `unreal_net_driver_v2` | Unreal Engine 5 custom net driver extensions |
| [ ] | 90 | `unity_transport` | Unity Transport Package wire format (UTP 2.x) |
| [ ] | 91 | `unity_ngo` | Unity Netcode for GameObjects serialization |
| [ ] | 92 | `unity_entities_netcode` | Unity Netcode for Entities (DOTS) transport |
| [ ] | 93 | `unity_relay` | Unity Relay service protocol |
| [ ] | 94 | `godot_enet` | Godot Engine ENet multiplayer peer |
| [ ] | 95 | `godot_websocket_mp` | Godot Engine WebSocket multiplayer peer |
| [ ] | 96 | `godot_rpc_mp` | Godot Engine high-level multiplayer RPC |
| [ ] | 97 | `o3de_aznetworking` | Open 3D Engine AzNetworking transport |
| [ ] | 98 | `cryengine_net_channel` | CRYENGINE NetChannel protocol |
| [ ] | 99 | `source2_netmessage` | Source 2 engine NetMessage serialization |
| [ ] | 100 | `source2_svcmsg` | Source 2 SVC_Messages (server-to-client) |

### 2.2 AAA Online Servis Protokolleri (12 adet)

| | # | Protokol | Açıklama |
|---|---|---|---|
| [ ] | 101 | `steam_datagram_relay` | Steam Datagram Relay (SDR) protocol |
| [ ] | 102 | `steam_sdr_relay_v3` | Steam Datagram Relay v3 TURN-like routing |
| [ ] | 103 | `steam_game_networking_s2` | Steam GameNetworkingSockets v2 |
| [ ] | 104 | `epic_online_eos_p2p` | Epic Online Services P2P transport |
| [ ] | 105 | `epic_online_voice` | EOS Voice chat protocol |
| [ ] | 106 | `epic_dtls_p2p` | Epic custom DTLS-based P2P transport |
| [ ] | 107 | `xbox_live_sdv2` | Xbox Live SDv2 (Secure Device Association) |
| [ ] | 108 | `xbox_live_mpsd` | Xbox Live Multiplayer Session Directory |
| [ ] | 109 | `xbox_reliable_udp` | Xbox Reliable UDP transport |
| [ ] | 110 | `psn_matchmaking_v3` | PlayStation Network matchmaking v3 |
| [ ] | 111 | `psn_rtc_signaling` | PSN RTC (Real-Time Communication) signaling |
| [ ] | 112 | `nintendo_npln_p2p` | Nintendo NPLN P2P matchmaking transport |

### 2.3 Battle Royale / FPS Networking (10 adet)

| | # | Protokol | Açıklama |
|---|---|---|---|
| [ ] | 113 | `fortnite_replay_stream` | Fortnite replay stream wire format |
| [ ] | 114 | `fortnite_server_replicator` | Fortnite server-side replicator actor |
| [ ] | 115 | `pubg_net_field_array` | PUBG net field fast-array delta compression |
| [ ] | 116 | `warzone_netcode_rigid` | Call of Duty Warzone rigid body net sync |
| [ ] | 117 | `valorant_fog_of_war` | Valorant Fog of War (anti-cheat visibility) |
| [ ] | 118 | `valorant_net_var` | Valorant network variable replication |
| [ ] | 119 | `apex_legends_netprop` | Apex Legends Source-based netprop extension |
| [ ] | 120 | `overwatch2_state_sync` | Overwatch 2 state synchronization protocol |
| [ ] | 121 | `cs2_subtick` | Counter-Strike 2 sub-tick system proto |
| [ ] | 122 | `rainbow6_seige_netvoice` | Rainbow Six Siege in-game voice + netcode hybrid |

### 2.4 Game Streaming / Cloud Gaming (10 adet)

| | # | Protokol | Açıklama |
|---|---|---|---|
| [ ] | 123 | `nvidia_gfn_stream` | NVIDIA GeForce NOW streaming protocol |
| [ ] | 124 | `nvidia_gfn_ctrl` | NVIDIA GFN control channel (input/feedback) |
| [ ] | 125 | `xcloud_fragment` | Xbox Cloud Gaming (xCloud) fragment protocol |
| [ ] | 126 | `xcloud_input_pipe` | xCloud low-latency input pipeline |
| [ ] | 127 | `stadia_controller_wifi` | Google Stadia WiFi controller protocol |
| [ ] | 128 | `luna_stream_proto` | Amazon Luna streaming transport |
| [ ] | 129 | `ps_remote_play_v3` | PlayStation Remote Play v3 protocol |
| [ ] | 130 | `steam_remote_play_together` | Steam Remote Play Together relay |
| [ ] | 131 | `steam_link_transport` | Steam Link transport protocol |
| [ ] | 132 | `moonlight_rtsp_game` | Moonlight/Sunshine game stream RTSP ext |

### 2.5 Metaverse / Social VR (8 adet)

| | # | Protokol | Açıklama |
|---|---|---|---|
| [ ] | 133 | `vrchat_udon_net` | VRChat Udon networking layer |
| [ ] | 134 | `vrchat_ik_sync` | VRChat IK (full-body) sync protocol |
| [ ] | 135 | `roblox_physics_replicator` | Roblox physics custom replication |
| [ ] | 136 | `roblox_voice_internal` | Roblox spatial voice internal transport |
| [ ] | 137 | `recroom_room_server` | Rec Room room-server protocol |
| [ ] | 138 | `horizon_worlds_sync` | Meta Horizon Worlds entity sync |
| [ ] | 139 | `spatial_io_webxr_sync` | Spatial.io WebXR object sync |
| [ ] | 140 | `secondlife_lludp` | Second Life LLUDP message template protocol |

### 2.6 Game Backend-as-a-Service (8 adet)

| | # | Protokol | Açıklama |
|---|---|---|---|
| [ ] | 141 | `playfab_party` | Microsoft PlayFab Party voice/chat transport |
| [ ] | 142 | `playfab_multiplayer_v2` | PlayFab multiplayer server allocation v2 |
| [ ] | 143 | `phaser_heroiclabs` | HeroicLabs Nakama (Phaser backend) binary protocol |
| [ ] | 144 | `darkrift2_netcode` | DarkRift 2 networking binary protocol |
| [ ] | 145 | `photon_realtime_v5` | Photon Realtime protocol v5 (binary) |
| [ ] | 146 | `photon_bolt_internal` | Photon Bolt internal determinism sync |
| [ ] | 147 | `fishnet_teleport` | Fish-Networking (Unity) teleport serialization |
| [ ] | 148 | `mirror_transport_fallback` | Mirror Networking fallback transport |

### 2.7 E-Spor ve Rekabetçi (7 adet)

| | # | Protokol | Açıklama |
|---|---|---|---|
| [ ] | 149 | `faceit_server_plugin` | FACEIT server plugin anti-cheat rpc |
| [ ] | 150 | `esea_client_anti_cheat` | ESEA client anti-cheat packet protocol |
| [ ] | 151 | `esl_wire_proto` | ESL Wire anti-cheat server verification |
| [ ] | 152 | `riot_vanguard_net` | Riot Vanguard kernel-to-userspace net intercept |
| [ ] | 153 | `battleye_packet_filter` | BattlEye packet filter signaling |
| [ ] | 154 | `easy_anti_cheat_stream` | Easy Anti-Cheat stream verification |
| [ ] | 155 | `denuvo_anti_tamper_net` | Denuvo Anti-Tamper online check-in protocol |

---

## 3. Yapay Zeka ve Büyük Dil Modeli (LLM) Trafik Protokolleri

> **Toplam:** 65 protokol | **Odak:** LLM inference, GPU interconnect, vector DB, model serving, training fabric

### 3.1 LLM Inference / Serving (12 adet)

| | # | Protokol | Açıklama |
|---|---|---|---|
| [ ] | 156 | `openai_realtime` | OpenAI Realtime API WebSocket protocol |
| [ ] | 157 | `openai_batch_api` | OpenAI Batch API async job protocol |
| [ ] | 158 | `openai_streaming_sse` | OpenAI streaming SSE token-level protocol |
| [ ] | 159 | `anthropic_messages_stream` | Anthropic Messages API streaming SSE extensions |
| [ ] | 160 | `anthropic_tool_use_bridge` | Anthropic tool_use content block bridge proto |
| [ ] | 161 | `google_gemini_stream` | Google Gemini API streaming gRPC-web proto |
| [ ] | 162 | `google_aistudio_ws` | Google AI Studio WebSocket connect proto |
| [ ] | 163 | `vllm_async_engine` | vLLM async engine scheduler IPC |
| [ ] | 164 | `tgi_messages` | HuggingFace TGI (Text Generation Inference) gRPC |
| [ ] | 165 | `triton_inference_grpc` | NVIDIA Triton Inference Server gRPC |
| [ ] | 166 | `triton_model_repo_stream` | Triton model repository file streaming |
| [ ] | 167 | `sglang_radix_cache` | SGLang RadixAttention cache sharing proto |

### 3.2 GPU Interconnect / Compute Fabric (12 adet)

| | # | Protokol | Açıklama |
|---|---|---|---|
| [ ] | 168 | `nvlink_fabric` | NVIDIA NVLink multi-node fabric protocol |
| [ ] | 169 | `nvswitch_telemetry` | NVIDIA NVSwitch internal telemetry |
| [ ] | 170 | `nvlink_c2c` | NVLink-C2C (chip-to-chip) interconnect proto |
| [ ] | 171 | `infiniband_rdmacm_v2` | InfiniBand RDMA CM (Connection Manager) v2 |
| [ ] | 172 | `infiniband_ipoib_enhanced` | IPoIB enhanced datagram mode |
| [ ] | 173 | `nvme_over_fabrics_tcp` | NVMe-oF (NVMe over Fabrics) TCP transport |
| [ ] | 174 | `gpu_direct_rdma` | NVIDIA GPUDirect RDMA peer-to-peer proto |
| [ ] | 175 | `gpu_direct_storage` | NVIDIA GPUDirect Storage (GDS) DMA proto |
| [ ] | 176 | `cxl_io_protocol` | CXL.io protocol (PCIe 5.0/6.0 CXL) |
| [ ] | 177 | `cxl_cache_protocol` | CXL.cache coherent caching protocol |
| [ ] | 178 | `cxl_memory_protocol` | CXL.mem memory access protocol |
| [ ] | 179 | `ucx_transport` | OpenUCX transport layer (UCX-IB, UCX-TCP) |

### 3.3 Distributed Training (10 adet)

| | # | Protokol | Açıklama |
|---|---|---|---|
| [ ] | 180 | `nccl_allreduce` | NVIDIA NCCL collective allreduce ring protocol |
| [ ] | 181 | `nccl_allgather` | NCCL allgather algorithm proto |
| [ ] | 182 | `nccl_broadcast` | NCCL broadcast tree protocol |
| [ ] | 183 | `fsdp_shard_state` | PyTorch FSDP shard state sync proto |
| [ ] | 184 | `deepspark_glootcp` | DeepSpeed Gloo-TCP custom allreduce backend |
| [ ] | 185 | `horovod_elastic` | Horovod elastic training worker discovery |
| [ ] | 186 | `megatron_tp_overlap` | Megatron-LM tensor parallelism overlap IPC |
| [ ] | 187 | `megatron_pipeline_flush` | Megatron-LM pipeline flush schedule proto |
| [ ] | 188 | `pytorch_rpc_framework` | PyTorch distributed RPC framework |
| [ ] | 189 | `jax_pjit_sharding` | JAX pjit GSPMD sharding communication |

### 3.4 Vector / Embedding Databases (8 adet)

| | # | Protokol | Açıklama |
|---|---|---|---|
| [ ] | 190 | `pinecone_grpc_index` | Pinecone gRPC index upsert/query protocol |
| [ ] | 191 | `pinecone_collection_stream` | Pinecone collection internal consistency stream |
| [ ] | 192 | `weaviate_graphql_grpc` | Weaviate GraphQL-over-gRPC internal |
| [ ] | 193 | `weaviate_hnsw_replication` | Weaviate HNSW index replication log |
| [ ] | 194 | `qdrant_raft_log` | Qdrant Raft consensus log replication |
| [ ] | 195 | `qdrant_quantization_sync` | Qdrant binary/splat quantization segment sync |
| [ ] | 196 | `milvus_proxy_grpc` | Milvus proxy-to-data-node gRPC |
| [ ] | 197 | `milvus_sealed_seg_stream` | Milvus sealed segment streaming protocol |

### 3.5 LLM Observability / Gateways (8 adet)

| | # | Protokol | Açıklama |
|---|---|---|---|
| [ ] | 198 | `openllmetry_otlp` | OpenLLMetry OTLP trace extensions for LLM |
| [ ] | 199 | `langfuse_ingest` | Langfuse trace ingestion API proto |
| [ ] | 200 | `mlflow_gateway` | MLflow AI Gateway route proto |
| [ ] | 201 | `liteserve_grpc` | LiteLLM proxy internal scoring/fallback proto |
| [ ] | 202 | `portkey_gateway_router` | Portkey Gateway router RPC |
| [ ] | 203 | `helicone_worker_queue` | Helicone async log worker queue proto |
| [ ] | 204 | `langsmith_trace_push` | LangSmith trace push internal |
| [ ] | 205 | `arize_phoenix_collect` | Arize Phoenix OTLP collector extensions |

### 3.6 On-Device / Edge AI (8 adet)

| | # | Protokol | Açıklama |
|---|---|---|---|
| [ ] | 206 | `coreml_model_compile_rpc` | Apple Core ML model compilation IPC (ANED) |
| [ ] | 207 | `apple_aneclientd` | Apple Neural Engine daemon (aneclientd) proto |
| [ ] | 208 | `qualcomm_snpe_hexagon` | Qualcomm SNPE Hexagon DSP RPC |
| [ ] | 209 | `mediatek_apusys_delegate` | MediaTek APUSYS NPU delegate IPC |
| [ ] | 210 | `google_edge_tpu_compiler` | Google Edge TPU compiler-to-runtime proto |
| [ ] | 211 | `samsung_exynos_npu` | Samsung Exynos NPU mailbox IPC |
| [ ] | 212 | `onnx_runtime_execution_provider` | ONNX Runtime EP (Execution Provider) bridge |
| [ ] | 213 | `openvino_npu_plugin` | Intel OpenVINO NPU plugin driver IPC |

### 3.7 AI Safety / Governance (7 adet)

| | # | Protokol | Açıklama |
|---|---|---|---|
| [ ] | 214 | `guardrails_ai_validator` | Guardrails AI output validation RPC |
| [ ] | 215 | `nemo_guardrails_http` | NVIDIA NeMo Guardrails server proto |
| [ ] | 216 | `openai_moderation_async` | OpenAI Moderation API async pipeline |
| [ ] | 217 | `anthropic_constitutional` | Anthropic Constitutional AI classifier proto |
| [ ] | 218 | `aegis_guard_llama` | NVIDIA Aegis content safety guard proto |
| [ ] | 219 | `llama_guard_safeguard` | Meta Llama Guard safeguard output format |
| [ ] | 220 | `azure_ai_content_safety` | Azure AI Content Safety streaming eval proto |

---

## 4. Gelişmiş IoT ve Endüstriyel Yapay Zeka Protokolleri

> **Toplam:** 65 protokol | **Odak:** Industry 4.0/5.0, edge AI inferencing, digital twin, smart grid, autonomous vehicle V2X

### 4.1 Endüstriyel Edge AI (10 adet)

| | # | Protokol | Açıklama |
|---|---|---|---|
| [ ] | 221 | `cognex_vision_protocol` | Cognex In-Sight vision system streaming proto |
| [ ] | 222 | `keyence_cv_x_ftp` | Keyence CV-X series image transfer protocol |
| [ ] | 223 | `basler_blaze_tof` | Basler blaze ToF camera gRPC streaming |
| [ ] | 224 | `flir_atlas_sdk` | FLIR Atlas SDK thermal streaming proto |
| [ ] | 225 | `sick_lidar_rms` | SICK LiDAR RMS (Robot Monitoring System) |
| [ ] | 226 | `velodyne_vlp_packet` | Velodyne VLP LiDAR raw packet format |
| [ ] | 227 | `ouster_lidar_tcp` | Ouster LiDAR TCP command protocol |
| [ ] | 228 | `intel_realsense_dds` | Intel RealSense DDS (ROS2) camera node |
| [ ] | 229 | `edge_impulse_studio_data` | Edge Impulse Studio data acquisition daemon |
| [ ] | 230 | `seeed_grove_vision_ai` | Seeed Grove Vision AI module WebSocket |

### 4.2 OPC UA / TSN / Time-Sensitive Networking (12 adet)

| | # | Protokol | Açıklama |
|---|---|---|---|
| [ ] | 231 | `opc_ua_pubsub_udp` | OPC UA PubSub UDP multicast (UADP) |
| [ ] | 232 | `opc_ua_pubsub_mqtt` | OPC UA PubSub MQTT JSON encoding |
| [ ] | 233 | `opc_ua_gds_push` | OPC UA Global Discovery Server push |
| [ ] | 234 | `opc_ua_alarm_condition` | OPC UA A&C (Alarms & Conditions) client |
| [ ] | 235 | `ieee802_1qbv_tas` | IEEE 802.1Qbv Time-Aware Shaper schedule |
| [ ] | 236 | `ieee802_1qbu_frame_preemption` | IEEE 802.1Qbu Frame Preemption MAC merge |
| [ ] | 237 | `ieee802_1qci_psfp` | 802.1Qci Per-Stream Filtering and Policing |
| [ ] | 238 | `ieee802_1as_rev` | IEEE 802.1AS-Rev (gPTP revision) |
| [ ] | 239 | `tsn_stream_reservation` | IEEE 802.1Qat SRP (Stream Reservation Protocol) |
| [ ] | 240 | `detnet_service_layer` | DetNet Service Layer (IETF draft) |
| [ ] | 241 | `tsn_universal_windows` | Microsoft TSN-capable NIC driver wire extensions |
| [ ] | 242 | `cc_link_ie_tsn` | CC-Link IE TSN (Mitsubishi FA) protocol |

### 4.3 Dijital İkiz (Digital Twin) Protokolleri (8 adet)

| | # | Protokol | Açıklama |
|---|---|---|---|
| [ ] | 243 | `azure_digital_twin_dtdl` | Azure Digital Twins DTDL model sync |
| [ ] | 244 | `aws_iot_twinmaker_knowledge` | AWS IoT TwinMaker Knowledge Graph sync |
| [ ] | 245 | `nvidia_omniverse_nucleus` | NVIDIA Omniverse Nucleus DB replication |
| [ ] | 246 | `nvidia_omniverse_usd_stream` | Omniverse USD (Universal Scene Description) stream |
| [ ] | 247 | `eclipse_ditto_twin` | Eclipse Ditto digital twin CRUD protocol |
| [ ] | 248 | `eclipse_vorto_sync` | Eclipse Vorto information model sync |
| [ ] | 249 | `siemens_mindsphere_twinsync` | Siemens MindSphere twin synchronization |
| [ ] | 250 | `ptc_thingworx_alwayson` | PTC ThingWorx AlwaysOn binary protocol |

### 4.4 Akıllı Şebeke / Enerji (8 adet)

| | # | Protokol | Açıklama |
|---|---|---|---|
| [ ] | 251 | `iec_61850_mms` | IEC 61850 MMS (Manufacturing Message Spec) |
| [ ] | 252 | `iec_61850_goose` | IEC 61850 GOOSE fast multicast |
| [ ] | 253 | `iec_61850_sv` | IEC 61850 Sampled Values (SV) streaming |
| [ ] | 254 | `iec_61850_r_goose` | IEC 61850 Routable-GOOSE (R-GOOSE over IP) |
| [ ] | 255 | `iec_61970_cim_xml` | IEC 61970 CIM (Common Information Model) XML |
| [ ] | 256 | `openadr_3_0` | OpenADR 3.0 demand-response protocol |
| [ ] | 257 | `ocpp_2_1` | OCPP 2.1 (Open Charge Point Protocol for EV) |
| [ ] | 258 | `iso_15118_v2g` | ISO 15118 vehicle-to-grid (V2G) protocol |

### 4.5 Otonom Araç / V2X / ADAS (10 adet)

| | # | Protokol | Açıklama |
|---|---|---|---|
| [ ] | 259 | `dsrc_wsmp` | IEEE 802.11p DSRC WSMP (WAVE Short Message) |
| [ ] | 260 | `c_v2x_pc5` | 3GPP C-V2X PC5 sidelink (Mode 4) |
| [ ] | 261 | `c_v2x_uu` | 3GPP C-V2X Uu interface (cellular) |
| [ ] | 262 | `sae_j2735_bsm` | SAE J2735 BSM (Basic Safety Message) |
| [ ] | 263 | `sae_j2735_spat` | SAE J2735 SPAT (Signal Phase and Timing) |
| [ ] | 264 | `autoware_zenoh` | Autoware (ROS2) Zenoh autonomous vehicle node |
| [ ] | 265 | `apollo_cyber_rtps` | Baidu Apollo Cyber RT fast RTPS transport |
| [ ] | 266 | `apollo_perception_bridge` | Apollo perception-to-planning bridge proto |
| [ ] | 267 | `tesla_fsd_inference` | Tesla FSD (Full Self-Driving) inference fabric proto |
| [ ] | 268 | `waymo_fleet_rpc` | Waymo Fleet response RPC proto |

### 4.6 Robotik ve ROS2 Ekosistemi (9 adet)

| | # | Protokol | Açıklama |
|---|---|---|---|
| [ ] | 269 | `ros2_dds_fastrtps` | ROS2 eProsima Fast DDS discovery (RTPS) |
| [ ] | 270 | `ros2_dds_cyclone` | ROS2 Eclipse Cyclone DDS (Iceoryx shared mem) |
| [ ] | 271 | `ros2_rmw_zenoh` | ROS2 rmw_zenoh middleware (peer-to-peer) |
| [ ] | 272 | `ros2_iceoryx` | ROS2 rmw_iceoryx shared memory transport |
| [ ] | 273 | `micro_ros_serial` | micro-ROS serial transport (XRCE-DDS + serial) |
| [ ] | 274 | `micro_ros_udp` | micro-ROS custom UDP transport |
| [ ] | 275 | `rosbridge_websocket_v3` | rosbridge_suite WebSocket protocol v3 |
| [ ] | 276 | `moveit2_motion_service` | MoveIt2 motion planning service RPC |
| [ ] | 277 | `isaac_sim_ros2_bridge` | NVIDIA Isaac Sim-to-ROS2 bridge proto |

### 4.7 Endüstriyel 5G / URLLC (8 adet)

| | # | Protokol | Açıklama |
|---|---|---|---|
| [ ] | 278 | `profisafe_over_5g` | PROFIsafe over 5G URLLC bridge |
| [ ] | 279 | `ethercat_over_tsn` | EtherCAT over TSN (EoE TSN profile) |
| [ ] | 280 | `profinet_cc_a` | PROFINET CC-A over 5G URLLC |
| [ ] | 281 | `modbus_tcp_secure` | Modbus/TCP Security (TLS profile, IETF draft) |
| [ ] | 282 | `hart_ip_advanced` | HART-IP Advanced (WirelessHART over IP) |
| [ ] | 283 | `opc_ua_fx_uafx` | OPC UA FX (Field eXchange) UAFX protocol |
| [ ] | 284 | `pubsub_5g_tsn` | OPC UA PubSub 5G TSN bridge |
| [ ] | 285 | `six_p_industrial_5g` | 6G-P Industrial 5G ultra-low-latency fabric |

---

## 5. Gelişmiş Şifreleme ve Kuantum Sonrası (Post-Quantum) Protokoller

> **Toplam:** 65 protokol | **Odak:** Post-quantum cryptography, TLS 1.4/1.5, zero-knowledge, homomorphic encryption, blockchain consensus

### 5.1 Post-Quantum TLS / PKI (12 adet)

| | # | Protokol | Açıklama |
|---|---|---|---|
| [ ] | 286 | `tls_hybrid_kem` | TLS 1.3 hybrid key exchange (ECDH + PQC KEM) |
| [ ] | 287 | `tls_kyber1024` | TLS Kyber-1024 kem (NIST ML-KEM-1024) |
| [ ] | 288 | `tls_dilithium5` | TLS Dilithium5 signature (NIST ML-DSA-87) |
| [ ] | 289 | `tls_sphincs_plus` | TLS SPHINCS+ (NIST SLH-DSA) signature |
| [ ] | 290 | `tls_frodo_kem` | TLS FrodoKEM-1344-AES hybrid exchange |
| [ ] | 291 | `tls_classic_mceliece` | TLS Classic McEliece KEM exchange |
| [ ] | 292 | `tls_bike_l5` | TLS BIKE L5 KEM exchange |
| [ ] | 293 | `tls_hqc` | TLS HQC (Hamming Quasi-Cyclic) KEM |
| [ ] | 294 | `x509_composite_certs` | X.509 composite (traditional + PQ) certificates |
| [ ] | 295 | `x509_alt_cms_pq` | X.509 Alternative CMS PQ signature |
| [ ] | 296 | `acme_pq_challenge` | ACME PQ-hybrid domain validation challenge |
| [ ] | 297 | `crl_merkle_tree_pq` | CRL Merkle-tree-based PQ revocation list |

### 5.2 Post-Quantum VPN / Tünel (7 adet)

| | # | Protokol | Açıklama |
|---|---|---|---|
| [ ] | 298 | `wireguard_pq_hybrid` | WireGuard PQ-hybrid key exchange (wg-pq) |
| [ ] | 299 | `wireguard_kyber_poly` | WireGuard Kyber + Poly1305 hybrid |
| [ ] | 300 | `ipsec_ikev2_pq` | IKEv2 with PQ DH groups (RFC 9382 PQC groups) |
| [ ] | 301 | `ipsec_ikev2_frodo` | IKEv2 with FrodoKEM extension |
| [ ] | 302 | `openvpn_pq_cipher` | OpenVPN 2.7+ PQC cipher negotiation |
| [ ] | 303 | `tailscale_pq_noise` | Tailscale Noise IK + PQ extension |
| [ ] | 304 | `nebula_pq_handshake` | Slack Nebula PQ handshake extension |

### 5.3 Kuantum Anahtar Dağıtımı (QKD) (8 adet)

| | # | Protokol | Açıklama |
|---|---|---|---|
| [ ] | 305 | `bb84_qkd_classical` | BB84 QKD classical post-processing channel |
| [ ] | 306 | `e91_qkd_entanglement` | E91 entanglement-based QKD classical channel |
| [ ] | 307 | `etsi_gs_qkd_014` | ETSI GS QKD 014 REST-based key delivery API |
| [ ] | 308 | `qkd_network_routing` | QKD network SDN routing protocol (ITU-T Q.4160) |
| [ ] | 309 | `decoy_state_bb84_err` | Decoy-state BB84 error reconciliation cascade |
| [ ] | 310 | `cascade_info_recon` | CASCADE information reconciliation proto (IR) |
| [ ] | 311 | `tweaked_ldpc_privacy_amp` | Tweak-based LDPC privacy amplification proto |
| [ ] | 312 | `quantum_repeater_link_layer` | Quantum repeater entanglement link layer |

### 5.4 Zero-Knowledge Proofs / SMPC (10 adet)

| | # | Protokol | Açıklama |
|---|---|---|---|
| [ ] | 313 | `zk_snark_groth16` | Groth16 zk-SNARK proof verification wire format |
| [ ] | 314 | `zk_snark_plonk` | PLONK universal zk-SNARK proof format |
| [ ] | 315 | `zk_stark_fri` | zk-STARK FRI (Fast Reed-Solomon IOPP) proof |
| [ ] | 316 | `bulletproofs_rangeproof` | Bulletproofs range proof protocol |
| [ ] | 317 | `zk_email_dkim` | zk-email DKIM regex proof verification |
| [ ] | 318 | `mpc_ggm_3party` | Goldreich-Goldwasser-Micali 3-party MPC proto |
| [ ] | 319 | `mpc_spdz_online` | SPDZ (Smart-Past Nielsen Damgård Zakarias) online phase |
| [ ] | 320 | `mpc_ttp_preprocessing` | MPC trusted-third-party preprocessing proto |
| [ ] | 321 | `pir_sealpir` | Private Information Retrieval SealPIR proto |
| [ ] | 322 | `pir_spiral_stream` | SPIRAL PIR streaming setup protocol |

### 5.5 Homomorfik Şifreleme (FHE) (7 adet)

| | # | Protokol | Açıklama |
|---|---|---|---|
| [ ] | 323 | `fhe_ckks_serialize` | CKKS homomorphic encryption ciphertext serialize |
| [ ] | 324 | `fhe_bfv_ciphertext` | BFV (Brakerski-Fan-Vercauteren) ciphertext wire |
| [ ] | 325 | `fhe_tfhe_bootstrapping` | TFHE gate bootstrapping RPC protocol |
| [ ] | 326 | `fhe_openfhe_pke` | OpenFHE public key encryption API |
| [ ] | 327 | `fhe_ibm_helib_op` | IBM HELib homomorphic operation pipeline |
| [ ] | 328 | `fhe_google_shell` | Google SHELL (Symmetric Homomorphic Encryption) |
| [ ] | 329 | `fhe_transpiler_cggi` | FHE Transpiler CGGI-to-TFHE bridge |

### 5.6 Blockchain / Web3 Konsensüs (12 adet)

| | # | Protokol | Açıklama |
|---|---|---|---|
| [ ] | 330 | `ethereum_devp2p_v5` | Ethereum discv5 (Node Discovery v5) protocol |
| [ ] | 331 | `ethereum_snap_sync` | Ethereum snap sync (state heal) proto |
| [ ] | 332 | `ethereum_consensus_p2p` | Ethereum Consensus Layer p2p (libp2p + SSZ) |
| [ ] | 333 | `ethereum_blob_sidecar` | EIP-4844 blob sidecar gossip protocol |
| [ ] | 334 | `solana_tpu_proto` | Solana TPU (Transaction Processing Unit) proto |
| [ ] | 335 | `solana_turbine_block` | Solana Turbine block propagation tree |
| [ ] | 336 | `solana_gulf_stream` | Solana Gulf Stream mempool forwarding |
| [ ] | 337 | `libp2p_gossipsub_v1_2` | libp2p GossipSub v1.3 mesh protocol |
| [ ] | 338 | `libp2p_kad_dht_v2` | libp2p Kademlia DHT (Amino DHT + provider) |
| [ ] | 339 | `libp2p_quic_transport` | libp2p QUIC transport (WebTransport + QUIC) |
| [ ] | 340 | `libp2p_webrtc_browser` | libp2p WebRTC browser-to-browser transport |
| [ ] | 341 | `hotstuff_consensus` | Diem/Libra2 HotStuff BFT consensus proto |

### 5.7 Kriptografik Donanım / TEE / HSM (9 adet)

| | # | Protokol | Açıklama |
|---|---|---|---|
| [ ] | 342 | `intel_sgx_dcap_quote` | Intel SGX DCAP quote verification extension |
| [ ] | 343 | `intel_tdx_attestation` | Intel TDX attestation protocol |
| [ ] | 344 | `amd_sev_snp_attest` | AMD SEV-SNP attestation report protocol |
| [ ] | 345 | `arm_cca_realm_attest` | Arm CCA Realm attestation token proto |
| [ ] | 346 | `pkcs11_3_1` | PKCS#11 v3.1 cryptographic token interface |
| [ ] | 347 | `tpm2_remote_attestation` | TPM 2.0 Remote Attestation DICE extension |
| [ ] | 348 | `hsm_kmip_2_1` | KMIP 2.1 Key Management Interoperability Protocol |
| [ ] | 349 | `gp_tui_tee` | GlobalPlatform TUI (Trusted UI) internal proto |
| [ ] | 350 | `aws_nitro_attestation` | AWS Nitro Enclave attestation extended |

---

## Önceliklendirme Matrisi

| Kategori | Toplam | Kritik | Yüksek | Orta | Düşük |
|----------|--------|--------|--------|------|-------|
| 1. Bulut / RPC | 85 | 12 | 28 | 30 | 15 |
| 2. Oyun / Eğlence | 70 | 10 | 25 | 22 | 13 |
| 3. AI / LLM | 65 | 18 | 22 | 15 | 10 |
| 4. IoT / Endüstriyel | 65 | 15 | 20 | 18 | 12 |
| 5. PQ / Şifreleme | 65 | 20 | 25 | 12 | 8 |
| **GENEL TOPLAM** | **350** | **75** | **120** | **97** | **58** |

### Kritiklik Kriterleri

- **Kritik:** Gerçek dünyada yaygın kullanım, güvenlik açısından zorunlu (TLS PQ, SGX/TDX attestation, NVIDIA NCCL, OpenAI Realtime)
- **Yüksek:** Büyüyen ekosistem, yakın gelecekte standartlaşması beklenen (OPC UA FX, Solana TPU, ROS2 Zenoh, NVLink-C2C)
- **Orta:** Niş ama stratejik öneme sahip (LLM Guard, zk-SNARK, Ditto, Game backend servisleri)
- **Düşük:** Spesifik vendor veya deneysel protokoller (özel game engine proto'ları, QKD routing)

---

## 6. 🧠 AI Traffic Analyzer Katmanı — "Nasıl Olmalı?"

> Bu bölüm, LLM token akışlarını gerçek zamanlı analiz edecek özel bir Netscope katmanının
> mimari tasarımını, gerekli protokol alanlarını, istatistik modelini ve uygulama yol haritasını tanımlar.

### 6.1 Katman Mimarisi

```
┌─────────────────────────────────────────────────────────────┐
│                    Netscope AI Traffic Analyzer              │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────┐  │
│  │ LLM Protocol │  │ Token Stream │  │ Prompt/Response    │  │
│  │ Dissectors   │→ │ Reassembler  │→ │ Pair Correlator    │  │
│  └─────────────┘  └──────────────┘  └─────────┬──────────┘  │
│                                                │             │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────▼──────────┐ │
│  │  Real-time   │  │  Latency     │  │  Token Statistics   │ │
│  │  Dashboard   │← │  Heatmap     │← │  Engine             │ │
│  └─────────────┘  └──────────────┘  └────────────────────┘  │
│                                                │             │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────▼──────────┐ │
│  │  Export      │  │  Anomaly     │  │  Cost Estimator     │ │
│  │  (JSON/OTLP) │  │  Detector    │  │  ($/1K tokens)      │ │
│  └─────────────┘  └──────────────┘  └────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### 6.2 Gerekli Yeni Protokol Dissector'ları

#### 6.2.1 LLM API Streaming Protokolleri (15 adet)

| | # | Protokol | Transport | Açıklama |
|---|---|---|---|---|
| [ ] | 351 | `openai_chat_stream` | HTTPS/SSE | OpenAI Chat Completions streaming (SSE `data: [DONE]`) |
| [ ] | 352 | `openai_realtime_ws` | WebSocket | OpenAI Realtime API binary/audio/text frames |
| [ ] | 353 | `openai_responses_api` | HTTPS/SSE | OpenAI Responses API streaming proto |
| [ ] | 354 | `anthropic_stream_evt` | HTTPS/SSE | Anthropic SSE event stream (`message_start/delta/stop`) |
| [ ] | 355 | `google_gemini_bidi` | WebSocket | Gemini bidirectional live API proto |
| [ ] | 356 | `google_gemini_rest_stream` | HTTPS/SSE | Gemini generateContent SSE streaming |
| [ ] | 357 | `azure_aoai_stream` | HTTPS/SSE | Azure OpenAI Service streaming (proprietary extensions) |
| [ ] | 358 | `cohere_stream_v2` | HTTPS/SSE | Cohere Generate/Stream v2 event protocol |
| [ ] | 359 | `mistral_chat_stream` | HTTPS/SSE | Mistral AI chat streaming proto |
| [ ] | 360 | `groq_lpcu_stream` | HTTPS/SSE | Groq LPU (Language Processing Unit) streaming |
| [ ] | 361 | `together_stream` | HTTPS/SSE | Together AI inference streaming |
| [ ] | 362 | `fireworks_stream` | HTTPS/SSE | Fireworks.ai streaming inference proto |
| [ ] | 363 | `deepseek_stream` | HTTPS/SSE | DeepSeek API streaming proto |
| [ ] | 364 | `xai_grok_stream` | HTTPS/SSE | xAI Grok API streaming WS proto |
| [ ] | 365 | `bedrock_invoke_stream` | HTTPS/SSE | AWS Bedrock InvokeModelWithResponseStream |

#### 6.2.2 LLM Proxy / Gateway Streaming (8 adet)

| | # | Protokol | Transport | Açıklama |
|---|---|---|---|---|
| [ ] | 366 | `litellm_proxy_stream` | HTTPS/SSE | LiteLLM proxy streaming relay proto |
| [ ] | 367 | `portkey_stream_relay` | HTTPS/SSE | Portkey gateway streaming relay |
| [ ] | 368 | `helicone_log_stream` | HTTPS | Helicone async log shipping proto |
| [ ] | 369 | `langfuse_ingest_v2` | HTTPS | Langfuse trace ingest v2 proto |
| [ ] | 370 | `mlflow_gateway_stream` | HTTPS/SSE | MLflow AI Gateway route streaming |
| [ ] | 371 | `openrouter_stream` | HTTPS/SSE | OpenRouter multi-provider SSE stream |
| [ ] | 372 | `cloudflare_ai_gateway` | HTTPS/SSE | Cloudflare AI Gateway WAF + streaming proxy |
| [ ] | 373 | `kong_ai_gateway_stream` | HTTPS/SSE | Kong AI Gateway LLM streaming middleware |

#### 6.2.3 Tokenizer / Encoding Protocol Metadata (6 adet)

| | # | Protokol | Açıklama |
|---|---|---|---|
| [ ] | 374 | `tiktoken_bpe_header` | OpenAI tiktoken BPE encoding metadata (cl100k_base, o200k_base) |
| [ ] | 375 | `sentencepiece_proto` | Google SentencePiece tokenizer model proto |
| [ ] | 376 | `huggingface_tokenizer_config` | HuggingFace `tokenizer.json` fast tokenizer metadata |
| [ ] | 377 | `gemma_tokenizer_header` | Google Gemma SentencePiece tokenizer variant |
| [ ] | 378 | `llama_tokenizer_header` | Meta Llama BPE tokenizer metadata exchange |
| [ ] | 379 | `anthropic_claude_tokenizer` | Anthropic Claude custom tokenizer header |

### 6.3 AI Traffic Analyzer — Veri Modeli ve Alanlar

Her yakalanan LLM paketi için aşağıdaki alanlar parse edilmeli ve istatistik motoruna beslenmelidir:

#### 6.3.1 Temel Akış Alanları (`ai_traffic` root struct)

```rust
/// AI Traffic Analyzer ana veri yapısı — her LLM istek/yanıt çifti için bir kayıt
struct AiTrafficRecord {
    // ── Oturum ──
    session_id:        Uuid,           // Tekil oturum tanımlayıcı (connection tracking)
    provider:          AiProvider,     // OpenAI | Anthropic | Google | Cohere | Mistral | Groq | Azure | ...
    model_name:        String,         // "gpt-4o", "claude-sonnet-5", "gemini-2.5-pro", ...
    endpoint_path:     String,         // "/v1/chat/completions", "/v1/messages", ...

    // ── Prompt / Request ──
    prompt_text_hash:  Sha256Digest,   // Prompt içeriğinin SHA-256 hash'i (PII koruma)
    prompt_char_count: u32,            // Prompt karakter sayısı
    prompt_token_count: u32,           // Prompt token sayısı (tokenizer'a göre hesaplanmış)
    system_prompt_hash: Sha256Digest,  // System prompt hash'i (ayrı takip)
    tool_def_count:    u8,             // Kaç adet tool/function tanımlandığı
    tools_total_chars: u32,            // Tool tanımlarının toplam karakter uzunluğu

    // ── Response / Token Stream ──
    response_total_tokens: u32,        // Toplam yanıt token sayısı
    completion_tokens:    u32,         // Sadece completion (deltas) token sayısı
    reasoning_tokens:     u32,         // Thinking/reasoning token sayısı (CoT modelleri)
    tool_call_tokens:     u32,         // Tool call request token sayısı
    first_token_latency_ms: u32,       // TTFT: Time-To-First-Token (ilk token gecikmesi)
    inter_token_avg_ms:    f32,        // Tokenlar arası ortalama gecikme (ms)
    inter_token_p50_ms:    f32,        // Tokenlar arası P50 gecikme
    inter_token_p95_ms:    f32,        // Tokenlar arası P95 gecikme
    inter_token_p99_ms:    f32,        // Tokenlar arası P99 gecikme
    tokens_per_second:     f32,        // Ortalama token/saniye çıkış hızı
    total_stream_duration_ms: u32,     // Tüm stream süresi (ilk byte → son byte)

    // ── Ağ Katmanı ──
    tcp_handshake_ms:      u32,        // TCP 3-way handshake süresi
    tls_handshake_ms:      u32,        // TLS 1.3 handshake süresi (total)
    tls_psk_resumption:    bool,       // TLS session resumption (0-RTT) kullanıldı mı?
    server_processing_ms:  u32,        // Sunucu tarafı işlem süresi (ttfb - tcp - tls)
    http_status:           u16,        // HTTP yanıt kodu (200, 429, 500, ...)
    retry_count:           u8,         // Kaç kez retry yapıldığı (429 rate-limit)

    // ── Maliyet ──
    prompt_cost_usd:       f64,        // Prompt maliyeti (USD)
    completion_cost_usd:   f64,        // Completion maliyeti (USD)
    total_cost_usd:        f64,        // Toplam maliyet (USD)
    cost_per_1k_input:     f64,        // Birim fiyat (input, $/1K token)
    cost_per_1k_output:    f64,        // Birim fiyat (output, $/1K token)

    // ── Meta ──
    timestamp_start:       Timestamp,  // İstek başlangıç zamanı (UTC)
    timestamp_first_token: Timestamp,  // İlk token alınma zamanı
    timestamp_end:         Timestamp,  // Stream bitiş zamanı
    geo_region:            Option<String>, // Sunucu bölgesi (CF-RAY / x-region header)
}
```

#### 6.3.2 Streaming Token Seviyesinde Parse

SSE (`text/event-stream`) ve WebSocket binary frame'leri için her bir token deltası ayrıştırılmalıdır:

| Sağlayıcı | Event Tipi | Delta Alanı | Sonlandırma İşareti |
|-----------|-----------|-------------|-------------------|
| OpenAI | `choices[0].delta.content` | JSON pointer `$.choices[0].delta.content` | `[DONE]` |
| Anthropic | `content_block_delta` | `delta.text` | `message_stop` |
| Gemini | `GenerateContentResponse` | `candidates[0].content.parts[0].text` | `finish_reason != FINISH_REASON_UNSPECIFIED` |
| Cohere | `text-generation` | `text` (delta) | `finish_reason == "COMPLETE"` |
| Mistral | `choices[0].delta.content` | OpenAI-uyumlu | `[DONE]` |
| Groq | `choices[0].delta.content` | OpenAI-uyumlu | `[DONE]` |
| DeepSeek | `choices[0].delta.content` | OpenAI-uyumlu | `[DONE]` |
| Bedrock | `chunk.bytes` | `bytes` → JSON parse → `completion` | `"completion":"<|endoftext|>"` |
| Azure | `choices[0].delta.content` | OpenAI-uyumlu + `apim-request-id` header | `[DONE]` |

#### 6.3.3 Prompt/Response Eşleştirme (Pair Correlation)

Her AI isteği ile yanıtı arasında birebir eşleştirme yapabilmek için:

```
┌──────────────────────────────────────────────────────────┐
│              Pair Correlation Stratejisi                   │
├──────────────────────────────────────────────────────────┤
│ 1. TCP Connection Tracking                                │
│    - 5-tuple (src_ip, src_port, dst_ip, dst_port, proto)  │
│    - HTTP/2 Stream ID aynı connection üzerinde multiplex  │
│                                                           │
│ 2. HTTP Header Korelasyonu                                │
│    - OpenAI:    x-request-id                              │
│    - Anthropic: request-id                                │
│    - Google:    x-goog-request-params (base64 decoded)    │
│    - Azure:     apim-request-id                           │
│    - Genel:     X-Trace-Id / traceparent (W3C Trace)     │
│                                                           │
│ 3. SSE Stream ID Tracking                                 │
│    - OpenAI:     stream_id (Response API)                 │
│    - Anthropic:  message_id → content_block sequence      │
│                                                           │
│ 4. Fallback: Timing-based (aynı TCP stream'deki ardışık   │
│    request-response çiftlerini zaman damgası ile eşle)     │
└──────────────────────────────────────────────────────────┘
```

### 6.4 Gerçek Zamanlı İstatistik Panosu (Live Dashboard)

#### 6.4.1 Anlık Metrikler (Per-Model)

| Metrik | Birim | Hesaplama | Eşik (Uyarı) |
|--------|-------|-----------|--------------|
| **TTFT** (Time-To-First-Token) | ms | `t_first_token - t_request_sent` | > 500ms ⚠️ |
| **TPOT** (Time-Per-Output-Token) | ms | `stream_duration / completion_tokens` | > 80ms ⚠️ |
| **Toks/Saniye** | token/s | `completion_tokens / (stream_duration_ms / 1000)` | < 20 ⚠️ |
| **Toplam Toks** | token | `prompt_tokens + completion_tokens` | — |
| **Maliyet/İstek** | $ | `prompt_cost + completion_cost` | > $0.10 ⚠️ |
| **Hata Oranı** | % | `(4xx + 5xx) / total_requests * 100` | > 5% 🔴 |
| **Rate Limit Oranı** | % | `429_count / total_requests * 100` | > 2% 🔴 |
| **Stream Kesintisi** | % | `incomplete_streams / total_streams * 100` | > 1% 🔴 |

#### 6.4.2 Dashboard Veri Akışı

```
┌──────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────┐
│ PCAP /   │ →  │ AI Traffic   │ →  │ In-Memory     │ →  │ TUI      │
│ Canlı    │    │ Dissector    │    │ Ring Buffer   │    │ Dashboard│
│ Yakalama │    │ Pipeline     │    │ (son 10K kayıt)│   │ (Ratatui)│
└──────────┘    └──────────────┘    └──────────────┘    └──────────┘
                                          │
                                          ▼
                                    ┌──────────────┐
                                    │ OTLP / JSON  │
                                    │ Export       │
                                    │ (Grafana,    │
                                    │  Datadog)    │
                                    └──────────────┘
```

#### 6.4.3 TUI Dashboard Bileşenleri

| Bileşen | İçerik | Güncelleme |
|---------|--------|------------|
| **Model Stats Tablosu** | Her model için TTFT, tok/s, cost, hata oranı | 1 saniye |
| **Token Akış Canlı** | Seçili stream'in token'ları kelime kelime akar | Gerçek zamanlı |
| **Prompt ↔ Response Görünümü** | Seçili request-response çifti yan yana | Talep üzerine |
| **Gecikme Heatmap** | Zaman × model matrisinde TTFT renk kodlaması | 5 saniye |
| **Maliyet Sayacı** | Oturum / günlük / aylık kümülatif maliyet | 1 saniye |
| **Anomali Uyarıları** | Eşik aşımı → kırmızı banner | Anlık |

### 6.5 Registry Entegrasyonu

Mevcut protocol registry'ye eklenecek alanlar:

```rust
// dissector_registry! makrosuna eklenecek yeni alanlar
dissector_registry! {
    // ... mevcut protokoller ...

    // AI Traffic Analyzer protokolleri
    (openai_chat_stream,   "OpenAI Chat Streaming",    Port(443), Transport::Tcp, Category::AiTraffic, Priority::Critical),
    (anthropic_stream_evt, "Anthropic SSE Stream",      Port(443), Transport::Tcp, Category::AiTraffic, Priority::Critical),
    (google_gemini_bidi,   "Gemini Bidirectional",      Port(443), Transport::Tcp, Category::AiTraffic, Priority::High),
    // ... diğerleri ...
}
```

Yeni `Category::AiTraffic` enum varyantı ile:
- **Filter menüsünde** "AI Traffic" sekmesi otomatik belirir
- **Color rule**'da AI protokolleri mor tonlarında renklendirilir
- **Education panelinde** "LLM Trafik Analizi" modülü aktif olur
- **Stats engine** otomatik olarak `AiTrafficRecord` alanlarını toplar

### 6.6 Uygulama Yol Haritası (AI Traffic Analyzer)

| Faz | Kapsam | Süre (tahmini) | Çıktı |
|-----|--------|---------------|-------|
| **Faz 1: Core Dissector** | OpenAI + Anthropic SSE dissector'ları, temel token sayımı | 3 hafta | `openai_chat_stream`, `anthropic_stream_evt` çalışır durumda |
| **Faz 2: Token Engine** | Tokenizer entegrasyonu (tiktoken, HuggingFace), prompt/response eşleştirme, TTFT hesaplama | 2 hafta | Token sayımı doğru, TTFT ölçülüyor |
| **Faz 3: Dashboard** | TUI dashboard (Ratatui), gerçek zamanlı metrik tablosu, maliyet hesaplayıcı | 3 hafta | Canlı dashboard, model bazlı karşılaştırma |
| **Faz 4: Genişletme** | Gemini, Cohere, Mistral, Bedrock, Groq dissector'ları | 2 hafta | 10+ sağlayıcı desteği |
| **Faz 5: Anomali & Export** | Anomali dedektörü, OTLP/JSON export, Grafana dashboard template | 2 hafta | Production-ready monitoring |
| **TOPLAM** | | **12 hafta** | Tam AI Traffic Analyzer |

### 6.7 AI Traffic Analyzer için Gerekli Ek Protokoller Özeti

| Alt Kategori | Protokol Sayısı |
|-------------|-----------------|
| LLM API Streaming | 15 |
| LLM Proxy / Gateway | 8 |
| Tokenizer Metadata | 6 |
| **TOPLAM** | **29** |

> Bu 29 protokol, mevcut 350 protokollük listeye ek olarak **AI Traffic Analyzer** katmanının çalışması için
> özel olarak tasarlanmıştır. Her biri SSE/WebSocket tabanlı streaming protokollerini çözümleyerek
> token-seviyesinde trafik analizi yapılmasını sağlar.

---

## 7. 🎮 Oyun Motoru Dissector Eklenti Sistemi — "Nasıl Olmalı?"

> Bu bölüm, yaygın oyun motorlarının (Unreal Engine, Unity) paket yapıları için topluluk
> tarafından desteklenen standart dissector eklentilerinin ana pakete nasıl dahil edilmesi
> gerektiğini ve oyun içi lag/senkronizasyon analizini kolaylaştıracak mimariyi tanımlar.

### 7.1 Temel Prensip: Eklenti Tabanlı Genişleme

Oyun protokolleri, genel ağ protokollerinden farklıdır:
- Her oyun motoru kendi replication/serialization sistemini kullanır
- Oyun güncellemeleriyle protokol sık sık değişir
- Community tarafından güncel tutulması gerekir

Bu nedenle **oyun motoru dissector'ları çekirdek (core) yerine eklenti (plugin) mimarisiyle** sunulmalıdır:

```
netscope/
├── dissectors/
│   ├── core/          ← Çekirdek protokoller (IP, TCP, UDP, TLS, HTTP, ...)
│   ├── game/          ← Oyun motoru eklentileri (plugin-based)
│   │   ├── unreal/
│   │   │   ├── iris_replication.rs      ← UE5 Iris
│   │   │   ├── replication_graph.rs     ← UE4 ReplicationGraph
│   │   │   ├── rpc_serialization.rs     ← UE RPC marshalling
│   │   │   └── plugin.toml              ← Eklenti metadata
│   │   ├── unity/
│   │   │   ├── transport_utp.rs         ← Unity Transport Package
│   │   │   ├── ngo_serialization.rs     ← Netcode for GameObjects
│   │   │   ├── entities_netcode.rs      ← Netcode for Entities
│   │   │   └── plugin.toml
│   │   ├── source2/
│   │   │   ├── netmessage.rs            ← Source 2 NetMessage
│   │   │   ├── svc_messages.rs          ← SVC_Messages
│   │   │   └── plugin.toml
│   │   └── godot/
│   │       ├── enet_peer.rs
│   │       ├── rpc_mp.rs
│   │       └── plugin.toml
```

### 7.2 Eklenti Manifestosu (`plugin.toml`)

```toml
[plugin]
name = "unreal-engine-dissector"
version = "1.3.0"
description = "Unreal Engine 4/5 replication ve RPC paket çözümleyici"
author = "Netscope Game Community"
license = "MIT"
repository = "https://github.com/netscope/game-dissectors"

[engine]
name = "Unreal Engine"
versions = ["4.27", "5.0", "5.1", "5.2", "5.3", "5.4", "5.5"]
net_driver = ["IpNetDriver", "SteamNetDriver", "OculusNetDriver"]

[protocols]
# Çözümlenen protokol adları → registry'ye kaydedilecek
protocols = [
    "unreal_iris",
    "unreal_replication_graph",
    "unreal_rpc_call",
    "unreal_fast_array",
    "unreal_channel_close",
]

[ports]
# Varsayılan portlar (oyun sunucusu başına değişebilir)
default = [7777, 7778, 27015, 27016]
range = "7777-7800"

[dependencies]
# Bağımlı olunan diğer eklentiler (örn. Steam Datagram Relay)
depends_on = ["steam_sdr"]

[files]
# Eklenti dosyaları
dissectors = [
    "iris_replication.rs",
    "replication_graph.rs",
    "rpc_serialization.rs",
]
test_pcaps = [
    "tests/ue5_empty_level.pcap",
    "tests/ue5_100_actors.pcap",
    "tests/ue5_rpc_call.pcap",
]
```

### 7.3 Oyun İçi Performans Analizi için Özel Alanlar

Her oyun paketi için aşağıdaki alanlar parse edilmeli:

#### 7.3.1 Genel Oyun Trafik Alanları

```rust
/// Oyun motoru bağımsız — tüm oyun dissector'larının sağlaması gereken ortak alanlar
struct GameTrafficRecord {
    // ── Bağlantı ──
    connection_id:      u64,            // Oyun oturumu bağlantı ID'si
    client_tick_rate:   u8,             // Client → Server tick rate (örn. 60Hz)
    server_tick_rate:   u8,             // Server → Client tick rate (örn. 30Hz)
    protocol_version:   u32,            // Oyun protokol versiyonu

    // ── Lag / Senkronizasyon ──
    ping_rtt_ms:         u16,           // Round-trip time (ICMP veya oyun-içi ping)
    client_send_time_ms: u32,           // Client gönderim zamanı (oyun içi timecode)
    server_recv_time_ms: u32,           // Server alım zamanı
    server_send_time_ms: u32,           // Server gönderim zamanı (ack/reply)
    client_recv_time_ms: u32,           // Client alım zamanı
    one_way_latency_ms:  i32,           // Tek yönlü gecikme tahmini
    jitter_ms:           f32,           // Jitter (paketler arası varyans)

    // ── Paket İstatistiği ──
    packet_seq:          u32,           // Sıra numarası
    packet_size:         u16,           // Paket boyutu (byte)
    is_reliable:         bool,          // Güvenilir UDP mi?
    was_resent:          bool,          // Tekrar gönderildi mi?
    ack_received_ms:     Option<u32>,   // ACK ne zaman alındı?

    // ── Kayıp / Hata ──
    packets_lost_in_window: u16,        // Son N paketteki kayıp sayısı
    loss_percentage:     f32,           // Kayıp oranı (%)
    out_of_order_count:  u16,           // Sıra dışı paket sayısı
    desync_flag:         bool,          // Senkronizasyon hatası tespit edildi mi?
    correction_delta:    Option<Vec<u8>>, // Düzeltme deltası (state correction)

    // ── İçerik ──
    actor_count:         u16,           // Replike edilen aktör sayısı
    replicated_props:    u16,           // Replike edilen property sayısı
    rpc_call_count:      u8,            // RPC çağrı sayısı
    is_initial_spawn:    bool,          // İlk spawn paketi mi?
    channel_id:          u8,            // Unreal Engine channel ID
    bunched_messages:    u8,            // Tek pakette kaç mesaj birleştirilmiş?
}
```

#### 7.3.2 Unreal Engine Spesifik Alanlar

```rust
/// Unreal Engine 4/5 paket yapısı
struct UnrealPacketHeader {
    // ── UDP Header Extension (UE5 Iris) ──
    magic:               u16,           // 0x9E2C veya custom magic
    protocol_version:    u8,            // UE Network Version (History: EPlotDirection::UE5_REPLICATION)
    connection_id:       u32,           // Bağlantı tekil ID'si
    packet_id:           u16,           // Paket sıra numarası

    // ── Bunch Header ──
    bunch_count:         u8,            // Bu paketteki bunch sayısı
    bunch_is_reliable:   bool,          // Reliable bunch?
    bunch_is_open:       bool,          // Açık bunch (partial)?
    bunch_is_close:      bool,          // Bunch kapandı mı?
    bunch_ch_index:      u8,            // Channel index (0=Control, 1=Actor, 2=Voice, ...)
    bunch_ch_seq:        u32,           // Channel-specific sequence

    // ── Replication ──
    rep_layout_version:  u8,            // ReplicationGraph layout version
    rep_node_count:      u16,           // ReplicationGraph node sayısı
    rep_is_dormant:      bool,          // Aktör dormant (replike edilmiyor)?
    rep_cull_distance:   f32,           // Cull mesafesi
    rep_priority:        f32,           // Replication önceliği

    // ── Iris Spesifik (UE5) ──
    iris_level_group:    u8,            // Iris level group
    iris_filter_status:  u8,            // Iris filter status
    iris_fast_array_idx: u16,           // FastArray index
    iris_delta_compressed: bool,        // Delta compression kullanıldı mı?
}
```

#### 7.3.3 Unity Transport / Netcode Alanları

```rust
/// Unity Transport Protocol (UTP) + Netcode
struct UnityTransportPacket {
    // ── UTP Header ──
    utp_magic:           u8,            // Bağlantı tipi (Request=0x02, Data=0x04, Disconnect=0x06)
    utp_connection_id:   u64,           // Bağlantı ID'si
    utp_packet_id:       u16,           // Paket sıra no
    utp_pipeline_id:     u8,            // Pipeline ID (ReliableSequenced, Unreliable, ...)

    // ── Netcode for GameObjects (NGO) ──
    ngo_message_type:    u8,            // 0x00=ConnectionRequest, 0x01=ConnectionApproved, ...
    ngo_network_id:      u64,           // NetworkObject global ID
    ngo_owner_id:        u64,           // Owner client ID
    ngo_is_spawn:        bool,          // Spawn mesajı mı?
    ngo_is_despawn:      bool,          // Destroy mesajı mı?
    ngo_rpc_id:          u32,           // RPC hash ID'si
    ngo_var_count:       u8,            // NetworkVariable sayısı
    ngo_scene_id:        u32,           // Sahne hash ID'si

    // ── Netcode for Entities (DOTS) ──
    ghost_count:         u16,           // Ghost entity sayısı (predicted/interpolated)
    ghost_snapshot_size: u16,           // Snapshot boyutu (byte)
    input_buffer_count:  u8,            // Input buffer'daki komut sayısı
    prediction_tick:     u32,           // Prediksiyon tick numarası
    interpolation_delay: f32,           // Enterpolasyon gecikmesi (tick cinsinden)
    command_ack_bits:    u64,           // Hangi komutların ACK'lendiği (bitfield)
}
```

### 7.4 Lag ve Senkronizasyon Analizi

#### 7.4.1 Lag Kaynağı Tespit Matrisi

| Gözlem | Olası Sebep | Bakılacak Alan |
|--------|-------------|----------------|
| `ping_rtt_ms` yüksek (>100ms) | Ağ gecikmesi | TCP katmanı, traceroute |
| `ping_rtt_ms` düşük ama `one_way_latency_ms` yüksek | Server tick rate düşük | `server_tick_rate` |
| `loss_percentage` > %2 | Paket kaybı | `packets_lost_in_window` |
| `out_of_order_count` > 0 | UDP reordering | `packet_seq` sırası |
| `jitter_ms` > 30ms | Ağ dalgalanması | `inter_packet_gap_ms` varyansı |
| `desync_flag == true` | State mismatch | `correction_delta` |
| `ack_received_ms == None` sık | ACK zaman aşımı | `was_resent` |
| `rep_cull_distance` çok düşük | Erken culling | ReplicationGraph konfigürasyonu |

#### 7.4.2 Zaman Çizelgesi Görünümü (Timeline)

```
Client Tick:     |███|   |███|   |███|   |███|   |███|
Client Send:     |──→|       |──→|       |──→|       |──→|
                 ↓               ↓               ↓
Network RTT:     ═══════╗   ═══════╗   ═══════╗
                        ║          ║          ║
Server Recv:          |←──|      |←──|      |←──|
Server Tick:     |███|███|███|███|███|███|███|███|  (daha yüksek tick rate)
Server Send:          |──→|      |──→|      |──→|
                 ═══════╝   ═══════╝   ═══════╝
                        ↓               ↓
Client Recv:          |←──|          |←──|
Client Render:  |███|███|███|███|███|███|███|███|

Interp Buffer:  |············|  ← Enterpolasyon gecikmesi
                |<── Lag ──→|  ← Algılanan toplam gecikme
```

> Bu timeline görünümü, her connection için TUI'da yatay kaydırmalı olarak gösterilmeli, anomali anları kırmızı ile işaretlenmelidir.

#### 7.4.3 Otomatik Teşhis Kuralları

```yaml
# Game Network Diagnostics Rules (YAML config — runtime yüklenir)
rules:
  - name: "Yüksek Ping"
    condition: "ping_rtt_ms > 150"
    severity: warning
    suggestion: "Sunucu bölgesini kontrol edin. Client ile server arasındaki coğrafi mesafe fazla olabilir."

  - name: "Paket Kaybı"
    condition: "loss_percentage > 2.0"
    severity: critical
    suggestion: "WiFi sinyal gücünü kontrol edin. Kablolu bağlantıya geçin. ISP'nizi kontrol edin."

  - name: "Düşük Server Tick Rate"
    condition: "server_tick_rate < 20"
    severity: warning
    suggestion: "Sunucu CPU limitine ulaşmış olabilir. Oyuncu/Aktör sayısını azaltın."

  - name: "Senkronizasyon Kopukluğu"
    condition: "desync_flag == true AND correction_delta.size > 256"
    severity: critical
    suggestion: "Client prediction ile server state arasında büyük fark var. Rubber-banding gözlemlenebilir."

  - name: "Jitter Spikes"
    condition: "jitter_ms > 50"
    severity: warning
    suggestion: "Ağda burst trafik var. Arka plan indirmelerini kontrol edin. QoS yapılandırması önerilir."

  - name: "RPC Flood"
    condition: "rpc_call_count > 100 PER PACKET"
    severity: warning
    suggestion: "Çok sayıda RPC tek pakette birikmiş. Bunching ayarlarını kontrol edin."
```

### 7.5 Community Dissector Paylaşım Sistemi

#### 7.5.1 Paket Yapısı

```
netscope-game-dissectors/
├── manifest.json              ← Tüm eklentilerin index'i
├── categories/
│   ├── game-engines/          ← Oyun motorları
│   │   ├── unreal/
│   │   ├── unity/
│   │   ├── source2/
│   │   ├── godot/
│   │   └── cryengine/
│   ├── anti-cheat/            ← Anti-cheat protokolleri
│   │   ├── vanguard/
│   │   ├── battleye/
│   │   └── eac/
│   └── platform-backends/     ← Platform servisleri
│       ├── steam/
│       ├── epic-online/
│       └── xbox-live/
└── tools/
    └── game-pcap-validator/   ← PCAP doğrulama aracı
```

#### 7.5.2 Community Katkı Akışı

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│ 1. Fork &    │ →  │ 2. Dissector │ →  │ 3. PR + PCAP │ →  │ 4. CI Test   │
│    Clone     │    │    Yaz       │    │    + Test     │    │    (pcap     │
│              │    │              │    │    Verisi     │    │    replay)   │
└──────────────┘    └──────────────┘    └──────────────┘    └──────┬───────┘
                                                                    │
┌──────────────┐    ┌──────────────┐    ┌──────────────┐            │
│ 7. Plugin    │ ←  │ 6. Release   │ ←  │ 5. Review    │ ←─────────┘
│    Store'da  │    │    (tag)     │    │    (maintainer│
│    Yayında   │    │              │    │     onayı)   │
└──────────────┘    └──────────────┘    └──────────────┘
```

### 7.6 Oyun Dissector Eklentileri için Gerekli Ek Protokoller Özeti

| Alt Kategori | Protokol Sayısı |
|-------------|-----------------|
| Unreal Engine (Iris, ReplicationGraph, RPC) | 6 |
| Unity (Transport, NGO, Entities, Relay) | 5 |
| Source 2 (NetMessage, SVC, UserMessage) | 4 |
| Godot (ENet, WebSocket MP, RPC) | 3 |
| Anti-Cheat (Vanguard, BattlEye, EAC, Denuvo) | 4 |
| Platform (Steam SDR, EOS P2P, Xbox SDv2, PSN RTC) | 4 |
| Lag/Diagnostic Metadata Protokolleri | 3 |
| **TOPLAM** | **29** |

> Bu 29 protokol, **oyun motoru eklenti sistemi** için gereken minimum seti oluşturur.
> 350 protokollük ana liste içindeki 70 oyun protokolüne ek olarak, bunlar tamamen
> **oyun içi lag/senkronizasyon analizi** odaklıdır.

---

## 8. 🔐 Kuantum Sonrası Kriptografi (PQC) İzleme Araçları — "Nasıl Olmalı?"

> Bu bölüm, post-quantum kriptografi geçiş sürecini izlemek için Netscope'a
> eklenmesi gereken PQC monitoring araçlarını ve protokollerini tanımlar.

### 8.1 PQC Adoption Tracker

Her TLS bağlantısında PQC kullanımını otomatik tespit eden ve raporlayan bir katman:

#### 8.1.1 PQC İzleme için Ek Protokol Metadata Alanları

| | # | Protokol | Açıklama |
|---|---|---|---|
| [ ] | 380 | `tls_pqc_handshake_ext` | TLS 1.3 PQC handshake extension dissector (hybrid KEM parsing) |
| [ ] | 381 | `tls_pqc_cert_chain` | X.509 PQC composite certificate chain parser |
| [ ] | 382 | `tls_pqc_migration_signal` | PQC migration signaling extension (RFC draft) |
| [ ] | 383 | `ikev2_pqc_dh_group` | IKEv2 PQC DH group negotiation dissector |
| [ ] | 384 | `wireguard_pqc_handshake` | WireGuard PQC handshake extension |
| [ ] | 385 | `ssh_pqc_kex` | OpenSSH 9.x PQC key exchange (sntrup761x25519-sha512) |
| [ ] | 386 | `dnssec_pqc_signing` | DNSSEC PQC signing algorithm (Falcon/Dilithium RRSIG) |
| [ ] | 387 | `pqc_cert_transparency` | Certificate Transparency with PQ-hybrid SCT |
| [ ] | 388 | `oqs_provider_telemetry` | Open Quantum Safe provider telemetry proto |
| [ ] | 389 | `pqc_hsm_bridge` | PQC-capable HSM-to-application bridge |

#### 8.1.2 PQC Handshake Veri Modeli

```rust
/// Her TLS bağlantısında PQC durumunu yakalayan yapı
struct PqcHandshakeRecord {
    // ── Handshake ──
    connection_5tuple:   FiveTuple,      // src_ip, src_port, dst_ip, dst_port, proto
    tls_version:         TlsVersion,     // 0x0304 = TLS 1.3, 0x0305 = TLS 1.4
    server_name:         String,         // SNI

    // ── Key Exchange ──
    client_kem_offers:   Vec<KemId>,     // Client'in sunduğu KEM algoritmaları
    server_kem_selected: Option<KemId>,  // Server'ın seçtiği KEM
    is_hybrid_kem:       bool,           // Hybrid (ECDH + PQC) kullanıldı mı?
    classical_group:     Option<NamedGroup>, // x25519, secp256r1, ...
    pqc_kem:             Option<PqcKem>, // Kyber1024, FrodoKEM-1344, BIKE-L5, ...
    shared_secret_size:  u16,            // Paylaşılan gizli anahtar boyutu (byte)

    // ── Signature ──
    cert_sig_algorithm:  SigAlgorithm,   // RSA-2048, ECDSA-P256, Dilithium5, ...
    is_pqc_signature:    bool,           // Sertifika PQC ile imzalanmış mı?
    is_composite_cert:   bool,           // Composite (geleneksel + PQC) sertifika mı?
    cert_chain_pqc_count: u8,            // Zincirde kaç PQC sertifikası var?

    // ── Performans ──
    pqc_kem_time_us:     u64,           // PQC KEM işlem süresi (mikrosaniye)
    pqc_sig_verify_us:   u64,           // PQC imza doğrulama süresi
    total_handshake_ms:  u32,           // Toplam handshake süresi
    pqc_overhead_ms:     i32,           // PQC'nin getirdiği ek süre (klasik handshake'e göre)
    pqc_packet_size_extra: u16,         // PQC'nin eklediği ek paket boyutu (byte)

    // ── Metadata ──
    timestamp:           Timestamp,
    is_success:          bool,           // Handshake başarılı mı?
    pqc_fallback_reason: Option<String>, // PQC başarısızsa fallback sebebi
}
```

#### 8.1.3 PQC Geçiş Dashboard'u

| Metrik | Açıklama | Hedef |
|--------|----------|-------|
| **PQC Adoption Rate** | PQC handshake / toplam TLS handshake % | İzleme (artış trendi) |
| **Hybrid vs Pure PQC** | Hybrid KEM vs sadece PQC KEM oranı | Geçiş sürecinde hybrid > %90 |
| **PQC Algorithm Distribution** | Kyber vs Frodo vs BIKE vs HQC kullanım dağılımı | Çeşitlilik sağlıklı |
| **PQC Overhead (Latency)** | PQC ek gecikmesi (ms) | < 50ms kabul edilebilir |
| **PQC Overhead (Bandwidth)** | PQC ek paket boyutu (KB) | < 10KB kabul edilebilir |
| **PQC Failure Rate** | PQC handshake başarısızlık oranı | < %1 |
| **PQC Certificate %** | PQC ile imzalanmış sertifika oranı | Artış trendi |
| **Fallback Reason Top-5** | En sık fallback sebepleri | Debugging |

---

## 9. 🏭 Özelleştirilmiş OPC UA / Endüstriyel Edge Protokolleri — "Nasıl Olmalı?"

> Bu bölüm, OPC UA ve endüstriyel edge bilişim protokollerinin Netscope'ta
> nasıl derinlemesine analiz edilmesi gerektiğini tanımlar.

### 9.1 OPC UA Derin Paket İnceleme (DPI) Katmanı

OPC UA binary (UA-TCP) ve hybrid (UA-SecureConversation) protokollerinin tam kapsamlı çözümlemesi:

#### 9.1.1 Gerekli OPC UA Ek Protokolleri

| | # | Protokol | Açıklama |
|---|---|---|---|
| [ ] | 390 | `opc_ua_binary_detail` | OPC UA binary encoding tam detay çözümleyici (NodeId, Variant, ExtensionObject) |
| [ ] | 391 | `opc_ua_secure_conversation` | OPC UA SecureConversation kanal detay analizi |
| [ ] | 392 | `opc_ua_pubsub_uadp_detail` | OPC UA PubSub UADP NetworkMessage detay parse |
| [ ] | 393 | `opc_ua_pubsub_json_detail` | OPC UA PubSub JSON NetworkMessage detay parse |
| [ ] | 394 | `opc_ua_gds_cert_push` | OPC UA GDS Certificate push/pull detay |
| [ ] | 395 | `opc_ua_companion_spec` | OPC UA Companion Specification metadata parser |
| [ ] | 396 | `opc_ua_alarm_shell` | OPC UA A&C (Alarms & Conditions) event detay |
| [ ] | 397 | `opc_ua_history_read_detail` | OPC UA Historical Access raw/processed data |
| [ ] | 398 | `opc_ua_reverse_connect` | OPC UA Reverse Connect (client-server rol değişimi) |
| [ ] | 399 | `opc_ua_mqtt_json_network` | OPC UA MQTT JSON NetworkMessage encoding |

#### 9.1.2 OPC UA Trafik Veri Modeli

```rust
/// OPC UA deep packet inspection record
struct OpcUaTrafficRecord {
    // ── Session ──
    session_id:             u32,            // OPC UA Session ID
    auth_token_id:          u32,            // AuthenticationToken ID
    secure_channel_id:      u32,            // SecureChannel ID
    endpoint_url:           String,         // opc.tcp://... veya https://...
    security_policy:        SecurityPolicy, // None, Basic128Rsa15, Basic256Sha256, Aes256-Sha256-RsaPss
    security_mode:          SecurityMode,   // None, Sign, SignAndEncrypt
    user_identity:          UserTokenType,  // Anonymous, UserName, X509, IssuedToken

    // ── Service Call ──
    service_type:           ServiceType,    // Read, Write, Browse, Subscribe, Call, ...
    request_handle:         u32,            // RequestHandle (eşleştirme için)
    status_code:            u32,            // OPC UA StatusCode
    service_timing_us:      u64,            // Servis çağrı süresi (mikrosaniye)

    // ── Node / Data ──
    node_id_count:          u16,            // Kaç NodeId okundu/yazıldı
    node_id_list:           Vec<NodeIdStr>, // ns=2;s=Temperature (ilk 50)
    total_value_bytes:      u32,            // Toplam değer boyutu (byte)
    data_type_count:        u8,             // Farklı veri tipi sayısı

    // ── PubSub ──
    pubsub_ds_group_id:     Option<u16>,    // DataSetGroup ID
    pubsub_writer_id:       Option<u16>,    // DataSetWriter ID
    pubsub_field_count:     Option<u16>,    // NetworkMessage içindeki field sayısı
    pubsub_sequence:        Option<u32>,    // Sequence number (kayıp tespiti)
    pubsub_qos:             Option<u8>,     // MQTT QoS seviyesi

    // ── Security Events ──
    is_bad_certificate:     bool,           // Sertifika hatası
    is_security_violation:  bool,           // SecurityPolicy ihlali
    is_access_denied:       bool,           // Yetki hatası (Bad_UserAccessDenied)
    is_subscription_late:   bool,           // Publish gecikti mi?
}
```

### 9.2 Endüstriyel Edge AI Protokol İzleme

#### 9.2.1 Gerekli Edge AI Protokolleri

| | # | Protokol | Açıklama |
|---|---|---|---|
| [ ] | 400 | `edge_inference_onnx` | ONNX Runtime edge inference IPC dissector |
| [ ] | 401 | `edge_tensorflow_lite` | TensorFlow Lite Micro inference proto |
| [ ] | 402 | `edge_pytorch_mobile` | PyTorch Mobile/Lite interpreter IPC |
| [ ] | 403 | `nxp_eiq_inference` | NXP eIQ (edge intelligence) inference proto |
| [ ] | 404 | `stm_stm32cube_ai` | STMicroelectronics STM32Cube.AI runtime proto |
| [ ] | 405 | `siemens_industrial_edge` | Siemens Industrial Edge runtime app-to-app IPC |
| [ ] | 406 | `bosch_nexeed_edge` | Bosch Nexeed edge analytics transport |
| [ ] | 407 | `beckhoff_twincat_analytics` | Beckhoff TwinCAT Analytics data streaming |
| [ ] | 408 | `rockwell_factorytalk_edge` | Rockwell FactoryTalk Edge Gateway proto |
| [ ] | 409 | `schneider_ecostruxure_edge` | Schneider EcoStruxure edge-to-cloud bridge |

### 9.3 Endüstriyel Edge + AI Birleşik Dashboard

```
┌──────────────────────────────────────────────────────────────────┐
│                  Industrial Edge AI Monitor                       │
├────────────┬────────────┬────────────┬────────────┬──────────────┤
│ OPC UA     │ PubSub     │ Edge AI    │ Security   │ Production   │
│ Services   │ Messages   │ Inference  │ Events     │ KPIs         │
├────────────┼────────────┼────────────┼────────────┼──────────────┤
│ Read: 1.2K │ Msg/sec: 45│ ONNX: 12ms │ CertOK: 3  │ OEE: 87.3%   │
│ Write: 340 │ Lost: 0    │ TFLite: 8ms│ BadAuth: 1 │ Downtime: 0  │
│ Browse: 56 │ SeqGap: 0  │ PTorch:15ms│ EncViol: 0 │ Cycle: 2.3s  │
│ Sub:  892  │ Qos0: 98%  │            │            │              │
└────────────┴────────────┴────────────┴────────────┴──────────────┘
```

---

## 10. 🏭 Proprietary Fieldbus Protokolleri için Zengin Decode Setleri — "Nasıl Olmalı?"

> Bu bölüm, fabrika otomasyonunda kullanılan proprietary (tescilli) fieldbus protokollerinin
> standart ve standart dışı versiyonları için Netscope'un nasıl zenginleştirilmiş çözümleme
> (decode) setleri sunması gerektiğini tanımlar.

### 10.1 Neden Özel Decode Setleri?

Fabrika otomasyonunda karşılaşılan temel sorunlar:

| Sorun | Açıklama | Etki |
|-------|----------|------|
| **Vendor fork'ları** | Siemens, Rockwell, Beckhoff gibi vendor'lar standart fieldbus protokollerini kendi ihtiyaçlarına göre genişletir | Standart dissector paketin %40-60'ını çözer, kalanı `Unknown Data` |
| **Firmware varyantları** | Aynı PLC modelinin farklı firmware'leri farklı frame formatları kullanır | Yanlış parse → yanlış teşhis |
| **Undocumented extensions** | Üreticinin yayınlamadığı özel servisler ve telemetry frame'leri | Güvenlik kör noktası |
| **Legacy + modern hibrit** | Aynı hatta PROFIBUS DP + PROFINET, Modbus RTU + Modbus/TCP aynı anda çalışır | Protokol karışıklığı |
| **Safety layer'lar** | PROFIsafe, CIP Safety gibi güvenlik katmanları fieldbus üzerine biner | Derinlemesine analiz zorluğu |

### 10.2 Kapsanması Gereken Proprietary Fieldbus Protokolleri

#### 10.2.1 Siemens Ekosistemi (12 adet)

| | # | Protokol | Açıklama | Non-Standart Genişletme |
|---|---|---|---|---|
| [ ] | 410 | `profinet_rt_siemens` | Siemens PROFINET RT (Real-Time) extended frame | Siemens özel alarm ve diyagnostik channel |
| [ ] | 411 | `profinet_irt_siemens` | Siemens PROFINET IRT (Isochronous) | Siemens sync domain extensions |
| [ ] | 412 | `profibus_dp_siemens` | Siemens PROFIBUS DP V2/V3 extensions | Siemens-specific DP-V2 acyclic services |
| [ ] | 413 | `s7comm_plus_detail` | Siemens S7Comm Plus (TIA Portal v13+) detaylı decode | TIA Portal job/ack mekanizması, firmware ≥ v4.0 |
| [ ] | 414 | `sinamics_drive_profile` | Siemens SINAMICS sürücü profili (ProfiDrive) | Siemens encoder emulation, safety limited speed |
| [ ] | 415 | `simatic_hmi_smartsrv` | Siemens SIMATIC HMI SmartServer özel katmanı | WinCC RT Advanced tag streaming |
| [ ] | 416 | `sinumerik_nck_channel` | Siemens SINUMERIK NCK channel protokolü | CNC özel G-code streaming + tool management |
| [ ] | 417 | `scalance_x_ring` | Siemens SCALANCE X endüstriyel ring redundancy | Siemens HRP (High-Speed Redundancy Protocol) client |
| [ ] | 418 | `siemens_l2_telegram` | Siemens Layer-2 discovery telegram (PROFINET DCP) | NameOfStation, IP assignment, factory reset |
| [ ] | 419 | `tia_portal_online_diag` | TIA Portal online diagnostics özel frame'leri | Module status, topology, firmware update trigger |
| [ ] | 420 | `siemens_opc_ua_model` | Siemens OPC UA Companion Model (SIMATIC S7-1500) | Siemens-specific NodeId namespace mapping |
| [ ] | 421 | `siemens_industrial_5g` | Siemens Industrial 5G private network management | Siemens-specific UPF/NEF extensions |

#### 10.2.2 Rockwell / Allen-Bradley Ekosistemi (10 adet)

| | # | Protokol | Açıklama | Non-Standart Genişletme |
|---|---|---|---|---|
| [ ] | 422 | `ether_net_ip_rockwell` | Rockwell EtherNet/IP CIP extended services | Rockwell-specific Class 1 implicit messaging extensions |
| [ ] | 423 | `cip_safety_rockwell` | Rockwell CIP Safety detaylı decode | GuardLogix-specific safety signature & timestamp |
| [ ] | 424 | `pccc_extended` | Allen-Bradley PCCC (Programmable Controller Commands) | PLC-5, SLC-500, MicroLogix extended command set |
| [ ] | 425 | `df1_full_duplex_ext` | Allen-Bradley DF1 Full-Duplex extended mode | BCC/CRC extended error-checking mode |
| [ ] | 426 | `studio5000_online_comm` | Studio 5000 Logix Designer online edit/fusion proto | Tag browser, cross-reference, online rung edit |
| [ ] | 427 | `factorytalk_view_hmi` | FactoryTalk View Machine Edition HMI proto | Rockwell tag alarm & data log subscription |
| [ ] | 428 | `stratix_switch_telemetry` | Rockwell Stratix switch (Cisco IE) extended telemetry | CIP-based port mirroring + QoS configuration |
| [ ] | 429 | `powerflex_drive_cip` | PowerFlex sürücü CIP energy object (Class 0x4E) | Rockwell-specific drive energy & torque profile |
| [ ] | 430 | `control_logix_backplane` | ControlLogix 1756 backplane bus decode | Multi-controller chassis ownership & redundancy |
| [ ] | 431 | `guard_i_o_safety` | Guard I/O safety module safe-state telemetry | Individual channel diagnostics & discrepancy time |

#### 10.2.3 Beckhoff / EtherCAT Ekosistemi (8 adet)

| | # | Protokol | Açıklama | Non-Standart Genişletme |
|---|---|---|---|---|
| [ ] | 432 | `ethercat_beckhoff_mdp` | Beckhoff EtherCAT MDP (Modular Device Profile) | Beckhoff-specific CoE (CANopen over EtherCAT) objects |
| [ ] | 433 | `ethercat_safety_beckhoff` | Beckhoff TwinSAFE/FailSafe over EtherCAT (FSoE) | Beckhoff safe logic editor connection validation |
| [ ] | 434 | `twincat_ads_detail` | Beckhoff TwinCAT ADS (Automation Device Specification) | AMS NetID routing, sum commands, notification |
| [ ] | 435 | `twincat_router_telemetry` | TwinCAT ADS Router telemetry stream | Real-time task jitter, cycle time exceed, CPU load |
| [ ] | 436 | `twincat_scope_view` | TwinCAT Scope View data streaming (YX data) | Multi-channel synchronized scope acquisition |
| [ ] | 437 | `ethercat_foe_detail` | EtherCAT FoE (File Access over EtherCAT) firmware ops | Beckhoff bootloader protocol & flash segment map |
| [ ] | 438 | `ethercat_distributed_clocks` | EtherCAT Distributed Clocks sync detail | Beckhoff DC mode selection & drift compensation |
| [ ] | 439 | `beckhoff_xplanar_mover` | Beckhoff XPlanar serbest hareketli taşıyıcı proto | Maglev mover position, tilt, and collision domain |

#### 10.2.4 Diğer Vendor Fieldbus'ları (10 adet)

| | # | Protokol | Açıklama | Non-Standart Genişletme |
|---|---|---|---|---|
| [ ] | 440 | `mitsubishi_melsec_proto` | Mitsubishi MELSEC MC protocol (binary & ASCII) | iQ-R/F/L series extended device memory map |
| [ ] | 441 | `mitsubishi_cc_link_ie_field` | Mitsubishi CC-Link IE Field basic extend | Motion CPU, simple motion module network var |
| [ ] | 442 | `omron_fins_udp_detail` | Omron FINS/UDP extended command decode | Sysmac NJ/NX series CIP routing, memory area |
| [ ] | 443 | `keyence_kv_ethernet` | Keyence KV-8000/Nano ethernet protocol | Keyence vision system trigger & result relay |
| [ ] | 444 | `b_r_automation_pvi` | B&R Automation PVI (Process Visualization Interface) | B&R Automation Studio PV transfer protocol |
| [ ] | 445 | `abb_robot_web_service` | ABB Robot Web Services (RW 7.x) motion data | ABB-specific RAPID-to-controller bridge proto |
| [ ] | 446 | `kuka_robot_sensor_interface` | KUKA Robot Sensor Interface (RSI) realtime xml | KUKA-specific sensor correction frame stream |
| [ ] | 447 | `fanuc_focas2` | FANUC FOCAS2 (CNC/PMC data window) protocol | FANUC-specific servo/spindle tuning parameters |
| [ ] | 448 | `yaskawa_memobus_tcp_detail` | Yaskawa MEMOBUS/TCP extended register access | Sigma-7 EtherCAT to MEMOBUS gateway |
| [ ] | 449 | `bosch_rexroth_open_core` | Bosch Rexroth Open Core Interface Protocol | IndraMotion MLC/XLC app-to-app bridge |

### 10.3 Decode Stratejisi: Katmanlı ve Eklenti Tabanlı

```
┌──────────────────────────────────────────────────────────────────┐
│                  Fieldbus Decode Mimarisi                          │
├──────────────────────────────────────────────────────────────────┤
│                                                                    │
│  ┌──────────────────────────────────────────────────────┐        │
│  │           Layer 3: Vendor-Specific Decode             │        │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │        │
│  │  │ Siemens  │ │ Rockwell │ │ Beckhoff │ │ Mitsubishi│ │        │
│  │  │ plugin   │ │ plugin   │ │ plugin   │ │ plugin   │ │        │
│  │  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ │        │
│  │       │            │            │            │         │        │
│  ├───────┴────────────┴────────────┴────────────┴─────────┤        │
│  │           Layer 2: Protocol Family Decode               │        │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐    │        │
│  │  │ PROFINET     │ │ EtherNet/IP  │ │ EtherCAT     │    │        │
│  │  │ Base Decode  │ │ Base Decode  │ │ Base Decode  │    │        │
│  │  └──────┬───────┘ └──────┬───────┘ └──────┬───────┘    │        │
│  │         │                │                │             │        │
│  ├─────────┴────────────────┴────────────────┴─────────────┤        │
│  │           Layer 1: Common Industrial Transport           │        │
│  │  ┌──────────────────────────────────────────────────┐   │        │
│  │  │ Ethernet (802.3), VLAN (802.1Q), TSN (802.1Qbv) │   │        │
│  │  └──────────────────────────────────────────────────┘   │        │
│  └──────────────────────────────────────────────────────┘        │
│                                                                    │
│  ┌──────────────────────────────────────────────────────┐        │
│  │              Decode Heuristic Engine                  │        │
│  │                                                       │        │
│  │  1. MAC OUI → Vendor tespiti                          │        │
│  │     Siemens:  00:1B:1B, 00:0E:8C, 00:1C:06           │        │
│  │     Rockwell: 00:00:BC, 00:1D:9C, 00:04:4C           │        │
│  │     Beckhoff: 00:01:05, 00:07:63, 70:B3:D5            │        │
│  │                                                       │        │
│  │  2. EtherType / FrameID → Protokol ailesi tespiti     │        │
│  │     0x8892: PROFINET RT/IRT                           │        │
│  │     0x88A4: EtherCAT                                  │        │
│  │     0x80E1: EtherNet/IP                               │        │
│  │                                                       │        │
│  │  3. Magic Byte / Service ID → Protokol varyantı       │        │
│  │     S7Comm: 0x32 → S7Comm Plus                        │        │
│  │     CIP:    Service 0x54 → Forward Open (Class 1)      │        │
│  │                                                       │        │
│  │  4. Firmware/Version → En doğru decode plugin seçimi  │        │
│  │     Vendor extension headers + version negotiation    │        │
│  └──────────────────────────────────────────────────────┘        │
└──────────────────────────────────────────────────────────────────┘
```

### 10.4 Vendor Plugin Manifestosu Örneği (`siemens-plugin.toml`)

```toml
[plugin]
name = "siemens-industrial-dissector"
version = "2.1.0"
description = "Siemens SIMATIC/SINUMERIK/SINAMICS proprietary protocol extensions"
author = "Netscope Industrial Community"
vendor = "Siemens AG"

[compatibility]
# Hangi base protokollerle çalışır
base_protocols = ["profinet_rt", "profinet_dcp", "s7comm", "ethercat"]
min_netscope_version = "0.9.0"

[vendor_signatures]
# MAC OUI'leri — otomatik vendor tespiti için
mac_ouis = ["00:1B:1B", "00:0E:8C", "00:1C:06", "28:63:36", "00:0F:D3"]
# PROFINET Vendor ID
pno_vendor_id = 0x002A
# PROFINET Device ID aralıkları
device_id_ranges = [
    { from = "0x0100", to = "0x01FF", family = "SIMATIC S7-1200" },
    { from = "0x0200", to = "0x02FF", family = "SIMATIC S7-1500" },
    { from = "0x0300", to = "0x03FF", family = "SIMATIC ET 200SP" },
    { from = "0x0400", to = "0x04FF", family = "SINAMICS S120" },
    { from = "0x0500", to = "0x05FF", family = "SINUMERIK 828D/840D" },
]

[firmware_variants]
# Aynı protokolün firmware'e göre farklı decode tabloları
[[firmware_variants.protocol]]
name = "s7comm_plus"
[[firmware_variants.protocol.variants]]
fw_range = ">= 4.0, < 5.0"
file = "s7comm_plus_v4.rs"
[[firmware_variants.protocol.variants]]
fw_range = ">= 5.0"
file = "s7comm_plus_v5.rs"

[protocols]
protocols = [
    "profinet_rt_siemens",
    "profinet_irt_siemens",
    "s7comm_plus_detail",
    "sinamics_drive_profile",
    "simatic_hmi_smartsrv",
    "sinumerik_nck_channel",
    "siemens_l2_telegram",
    "tia_portal_online_diag",
]

[ports]
default = [102, 34964, 135, 443]
udp_ports = [34964, 2222, 2223]

[files]
dissectors = [
    "profinet_rt_siemens.rs",
    "s7comm_plus_detail.rs",
    "sinamics_drive_profile.rs",
    "simatic_hmi_smartsrv.rs",
    "sinumerik_nck_channel.rs",
    "siemens_l2_telegram.rs",
    "tia_portal_online_diag.rs",
    "siemens_opc_ua_model.rs",
]
test_pcaps = [
    "tests/s7-1500_tia_v17.pcap",
    "tests/s7-1200_basic_read.pcap",
    "tests/profinet_irt_sync.pcap",
    "tests/sinamics_s120_telegram.pcap",
    "tests/sinumerik_840d_nck.pcap",
]
```

### 10.5 Proprietary Fieldbus Trafik Veri Modeli

```rust
/// Vendor-bağımsız endüstriyel alan veriyolu kaydı
struct FieldbusDecodeRecord {
    // ── Katman 1: Fiziksel / Link ──
    mac_src:             MacAddress,
    mac_dst:             MacAddress,
    ethertype:           u16,              // 0x8892 (PROFINET), 0x88A4 (EtherCAT), ...
    vlan_id:             Option<u16>,
    vlan_priority:       Option<u8>,       // PCP (802.1Q)
    is_tsn_frame:        bool,             // TSN stream mi?

    // ── Katman 2: Protokol Ailesi ──
    protocol_family:     FieldbusFamily,   // Profinet, EtherNetIP, EtherCAT, Modbus, ...
    frame_id:            u16,              // Protokol ailesine özgü frame ID
    cycle_counter:       u16,              // Çevrim sayacı
    data_status:         DataStatus,       // GOOD, BAD, REPLACEMENT, DEFAULT
    transfer_status:     TransferStatus,   // OK, ERROR, TIMEOUT

    // ── Katman 3: Vendor Extension ──
    vendor_name:         Option<VendorId>, // Siemens, Rockwell, Beckhoff, Mitsubishi, ...
    vendor_oui:          Option<[u8; 3]>,  // MAC OUI
    vendor_device_id:    Option<u16>,      // PROFINET Device ID
    vendor_fw_major:     Option<u16>,      // Firmware major versiyon
    vendor_fw_minor:     Option<u16>,      // Firmware minor versiyon
    vendor_extension_id: Option<u32>,      // Vendor-specific extension magic

    // ── Data Payload ──
    io_data_length:      u16,              // I/O verisi uzunluğu (byte)
    io_module_count:     u8,               // I/O modül sayısı
    process_data_quality: ProcessDataQuality, // FULL, SUBSTITUTE, FORCE, SIMULATED
    alarm_count:         u8,               // Aktif alarm/event sayısı
    diagnostic_data_len: u16,              // Diyagnostik veri uzunluğu

    // ── Safety Layer (varsa) ──
    has_safety_layer:    bool,             // PROFIsafe / CIP Safety / FSoE var mı?
    safety_connection_id: Option<u16>,
    safety_crc_valid:    Option<bool>,     // Safety CRC geçerli mi?
    safety_watchdog_ms:  Option<u16>,      // Safety watchdog süresi

    // ── Timing ──
    frame_send_time_ns:  u64,              // Gönderim zamanı (nanosaniye, TSN timestamp)
    cycle_time_us:       u32,              // Çevrim süresi (mikrosaniye)
    jitter_ns:           i64,              // Jitter (hedef çevrimden sapma)
    is_late:             bool,             // Çevrim gecikti mi?
    propagation_delay_ns: u32,             // Hat yayılım gecikmesi (IRT/DC)

    // ── Çözümleme Kalitesi ──
    decode_coverage_pct: u8,              // Paketin yüzde kaçı çözülebildi? (hedef > 95%)
    unknown_bytes:       u16,              // Çözülemeyen byte sayısı
    decode_layer:        DecodeLayer,      // L1_Only, L2_BaseFamily, L3_VendorFull
    needs_plugin_update: bool,             // Plugin güncellenmeli mi? (bilinmeyen extension)
}
```

### 10.6 Decode Kalite Skoru ve Eksik Tespit Uyarısı

```
┌──────────────────────────────────────────────────────────────────┐
│              Decode Quality Indicator (TUI'da gösterim)           │
├──────────────────────────────────────────────────────────────────┤
│                                                                    │
│  Paket #1247 ── PROFINET RT ── Siemens S7-1500                    │
│                                                                    │
│  ████████████████████████████████████░░░░  %92 çözüldü            │
│                                                                    │
│  ✓ L1 Ethernet      : OK (14 bytes)                               │
│  ✓ L2 PROFINET RT   : OK (58 bytes)  ── FrameID: 0xC000           │
│  ✓ L3 Siemens Ext   : OK (124 bytes) ── S7Comm Plus v5.0          │
│  ✗ Unknown trailer  : 24 bytes       ── ⚠️  Plugin güncellemesi  │
│                                           gerekebilir              │
│                                                                    │
│  [🔄 Plugin Güncelle]  [📤 Topluluğa Bildir]  [📋 Ham Hex Gör]   │
│                                                                    │
└──────────────────────────────────────────────────────────────────┘
```

### 10.7 Proprietary Fieldbus için Gerekli Ek Protokoller Özeti

| Alt Kategori | Protokol Sayısı |
|-------------|-----------------|
| Siemens ekosistemi | 12 |
| Rockwell / Allen-Bradley ekosistemi | 10 |
| Beckhoff / EtherCAT ekosistemi | 8 |
| Diğer vendor (Mitsubishi, Omron, Keyence, B&R, ABB, KUKA, FANUC, Yaskawa, Bosch) | 10 |
| **TOPLAM** | **40** |

---

## 11. 🔐 TLS 1.3 PQC Akıllı Sihirbaz — "Nasıl Olmalı?"

> Bu bölüm, TLS 1.3 ve PQC uzantılarının anahtar değişim süreçlerini,
> olası zafiyetlerini ve performans kayıplarını **tek tıkla** raporlayan
> akıllı bir sihirbazın (wizard) mimarisini tanımlar.

### 11.1 Sihirbazın Amacı ve Kapsamı

TLS 1.3 + PQC ekosistemi hızla karmaşıklaşıyor:
- **10+ PQC KEM algoritması** (Kyber, FrodoKEM, BIKE, HQC, Classic McEliece, ...)
- **Hybrid exchange** (ECDH + PQC bir arada)
- **Composite certificates** (RSA + Dilithium aynı zincirde)
- **Her kombinasyonun farklı performans ve güvenlik profili var**

Sihirbaz, bu karmaşıklığı tek bir "Analiz Et" butonuna indirgemelidir.

### 11.2 Tek Tık Rapor Akışı

```
┌──────────────────────────────────────────────────────────────────┐
│                   TLS 1.3 PQC Akıllı Sihirbaz                     │
├──────────────────────────────────────────────────────────────────┤
│                                                                    │
│  [1] PCAP / Canlı trafik seç                                      │
│       ↓                                                           │
│  [2] "🔍 Analiz Et" butonu → Otomatik TLS oturum taraması         │
│       ↓                                                           │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │              4 Aşamalı Otomatik Analiz Pipeline               │ │
│  │                                                               │ │
│  │  Aşama 1: Handshake Mapping                                   │ │
│  │  ├─ Tüm TLS ClientHello → ServerHello çiftlerini bul          │ │
│  │  ├─ KEM negotiation sırasını çıkar (offered → selected)       │ │
│  │  ├─ Sertifika zincirini ayrıştır (PQC imza tespiti)           │ │
│  │  └─ Her oturumu unique ID ile etiketle                        │ │
│  │                                                               │ │
│  │  Aşama 2: KEM/Anahtar Değişim Analizi                         │ │
│  │  ├─ ClientHello supported_groups extension → PQC grupları     │ │
│  │  ├─ ServerHello key_share → Seçilen PQC KEM                  │ │
│  │  ├─ Hybrid exchange tespiti (birden fazla key_share)          │ │
│  │  ├─ shared_key boyutu ve entropi hesaplaması                  │ │
│  │  └─ KEM işlem süresi tahmini (RTT/2 eksiği yöntemi)          │ │
│  │                                                               │ │
│  │  Aşama 3: Zafiyet ve Risk Taraması                            │ │
│  │  ├─ Bilinen zayıf PQC parametre setlerini tara                │ │
│  │  ├─ Sertifika zincirinde weak hash (SHA-1) kontrolü           │ │
│  │  ├─ Fallback to classical only tespiti (downgrade attack?)    │ │
│  │  ├─ TLS 1.2 fallback (PQ desteği yok, riskli)                 │ │
│  │  ├─ 0-RTT early data ile PQC uyumsuzluğu                      │ │
│  │  └─ CVE veritabanı ile cross-check (NIST IR 8454 güncelleme)  │ │
│  │                                                               │ │
│  │  Aşama 4: Performans Etki Raporu                              │ │
│  │  ├─ PQC vs klasik handshake süresi karşılaştırması            │ │
│  │  ├─ PQC ek paket boyutu (ClientHello şişmesi, ~1-10KB)       │ │
│  │  ├─ Sertifika zinciri transfer süresi                          │ │
│  │  ├─ PQC imza doğrulama maliyeti (client/server tarafı)        │ │
│  │  └─ Genel throughput etkisi (özellikle IoT/gömülü cihazlar)   │ │
│  └──────────────────────────────────────────────────────────────┘ │
│       ↓                                                           │
│  [3] 📊 İnteraktif rapor görüntüleme                               │
│       ↓                                                           │
│  [4] 📄 PDF/JSON/HTML export                                       │
│                                                                    │
└──────────────────────────────────────────────────────────────────┘
```

### 11.3 Zafiyet Tarama Kuralları (YAML kurallar seti)

```yaml
# PQC Vulnerability & Risk Rule Set
# Her kural, bir TLS 1.3 PQC oturumunda taranacak potansiyel sorunu tanımlar

rules:
  # ─── NIST PQC Standardization ───
  - id: "PQC-001"
    name: "Zayıf PQC Parametre Seti"
    description: "NIST onaylı olmayan veya eski round-3 parametreleri kullanılıyor"
    condition: "pqc_kem IN ['Kyber-512', 'NTRU-HPS-2048-509', 'SIKE-p434']"
    severity: critical
    impact: "Bu parametre setleri NIST tarafından standardize edilmemiş veya kırılmıştır. Kyber-768/1024 veya ML-KEM-768/1024 kullanılmalı."
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    fix: "Kyber-1024 (ML-KEM-1024) veya FrodoKEM-1344-AES kullanın."

  - id: "PQC-002"
    name: "Sadece Klasik Key Exchange"
    description: "TLS 1.3 bağlantısı sadece ECDH kullanıyor, PQC KEM sunulmamış"
    condition: "pqc_kem == None AND tls_version == '1.3'"
    severity: medium
    impact: "Harvest Now, Decrypt Later (HNDL) saldırısına karşı korumasız. Uzun ömürlü veriler risk altında."
    suggestion: "En azından hybrid ECDH + PQC KEM etkinleştirin."
    harvest_now_risk: "10+ yıl koruma gerekiyorsa kritik olarak işaretle."

  - id: "PQC-003"
    name: "TLS 1.2 Fallback (PQC Yok)"
    description: "PQC desteklemeyen TLS 1.2'ye düşüş tespit edildi"
    condition: "tls_version == '1.2' AND prev_connection_had_pqc == true"
    severity: high
    impact: "Olası downgrade attack veya yanlış yapılandırılmış load balancer. PQC koruması tamamen kaybolur."
    suggestion: "TLS 1.2'yi devre dışı bırakın veya TLS 1.2'ye PQC cipher suite'leri ekleyin."

  # ─── Certificate Chain ───
  - id: "PQC-004"
    name: "Composite Sertifika Zincirinde Klasik Zayıf İmza"
    description: "Composite (hibrit) sertifika zincirinde SHA-1 veya RSA-1024 var"
    condition: "is_composite_cert == true AND (cert_sig_hash == 'SHA-1' OR rsa_key_size < 2048)"
    severity: critical
    impact: "En zayıf halka tüm zinciri kırar. PQC imzaları güçlü olsa da klasik taraf zayıfsa tüm güvenlik çöker."
    suggestion: "Composite sertifikada klasik imza en az RSA-3072 + SHA-384 veya ECDSA-P384 + SHA-384 olmalı."

  - id: "PQC-005"
    name: "Self-Signed PQC Sertifika"
    description: "PQC algoritmasıyla imzalanmış self-signed sertifika"
    condition: "is_pqc_signature == true AND cert_chain_length == 1 AND issuer == subject"
    severity: info
    impact: "Test/dev ortamı olabilir. Production'da güvenilir bir CA'dan PQC sertifika alınmalı."

  # ─── Performance ───
  - id: "PQC-006"
    name: "Aşırı ClientHello Şişmesi"
    description: "PQC KEM offer'ları ClientHello'yu 10KB üzerine çıkarmış"
    condition: "client_hello_size > 10240"
    severity: warning
    impact: "TCP fragmentation, UDP'de MTU sorunları, gömülü cihazlarda bellek taşması."
    suggestion: "KEM tekliflerini en güçlü 2-3 taneye düşürün. Gereksiz NTRU/SIKE vb. teklifleri kaldırın."

  - id: "PQC-007"
    name: "Yavaş PQC Handshake"
    condition: "pqc_overhead_ms > 100"
    severity: warning
    impact: "Kullanıcı deneyimi bozulur. Mobil/IoT cihazlarda bağlantı zaman aşımı riski."
    suggestion: "Daha hızlı bir PQC KEM (Kyber-768, BIKE-L1) veya session resumption (PSK) kullanın."

  - id: "PQC-008"
    name: "0-RTT Early Data + PQC Kullanımı"
    condition: "is_0rtt == true AND pqc_kem != None"
    severity: high
    impact: "0-RTT early data replay atağına açık. PQC anahtar değişimi sırasında early data'nın güvenliği garanti edilemez."
    suggestion: "PQC bağlantılarda 0-RTT'yi devre dışı bırakın veya anti-replay mekanizması (ClientHello.random) emin olun."

  # ─── Downgrade / Injection ───
  - id: "PQC-009"
    name: "PQC Offer Strip Saldırısı Göstergesi"
    condition: "client_hello_has_pqc == true AND server_hello_has_pqc == false AND server_cert_has_pqc == true"
    severity: critical
    impact: "Client PQC teklif etmesine rağmen server PQC KEM seçmemiş. Olası MITM strip attack."
    suggestion: "Ağ yolunu kontrol edin. Middlebox'ların TLS extension'ları filtrelemediğinden emin olun."

  - id: "PQC-010"
    name: "Expired PQC Certificate"
    condition: "is_pqc_signature == true AND cert_not_after < now()"
    severity: high
    impact: "PQC sertifikasının süresi dolmuş. Fallback klasik imzaya kalır."
    suggestion: "PQC sertifikalarını otomatik yenileme (ACME PQ) yapılandırın."
```

### 11.4 Sihirbaz Veri Modeli

```rust
/// TLS 1.3 PQC Sihirbazı — tek bir oturumun tam analiz kaydı
struct TlsPqcWizardReport {
    // ── Oturum ──
    session_id:              Uuid,
    server_name:             String,           // SNI
    server_ip:               IpAddr,
    server_port:             u16,
    timestamp:               Timestamp,

    // ── TLS El Sıkışma ──
    tls_version:             TlsVersion,       // 0x0304 = TLS 1.3
    client_hello_size:       u16,              // Byte
    server_hello_size:       u16,
    total_handshake_bytes:   u32,              // Client + Server toplam byte
    handshake_duration_ms:   u32,

    // ── Key Exchange (KEM) ──
    client_kem_offers:       Vec<KemDetail>,   // Client'in teklif ettiği tüm KEM'ler
    server_kem_selected:     Option<KemDetail>,// Server'ın seçtiği KEM
    is_hybrid:               bool,             // Hybrid (ECDH + PQC) mi?
    classical_key_share:     Option<NamedGroup>, // x25519, secp256r1
    shared_secret_entropy:   u16,              // Bit cinsinden entropi (örn. 256)
    estimated_kem_time_us:   u64,              // Tahmini KEM işlem süresi

    // ── X.509 Sertifika Zinciri ──
    cert_chain_length:       u8,
    leaf_is_pqc_signed:      bool,
    leaf_sig_algorithm:      SigAlgorithm,     // Dilithium5, Falcon-1024, RSA-4096, ...
    intermediate_pqc_count:  u8,               // Ara CA'lerde PQC imza sayısı
    root_is_pqc:             bool,
    is_composite_cert:       bool,             // Composite (klasik + PQ bir arada)
    cert_valid_days_left:    i32,              // Gün cinsinden geçerlilik süresi

    // ── Güvenlik Değerlendirmesi ──
    vulnerabilities:         Vec<VulnerabilityFinding>,  // Tespit edilen zafiyetler
    risk_score:              RiskScore,        // LOW, MEDIUM, HIGH, CRITICAL
    cvss_vector:             Option<String>,   // En yüksek CVSS vektörü
    is_harvest_now_risk:     bool,             // HNDL saldırısı riski var mı?
    is_downgrade_suspicious: bool,             // Downgrade şüphesi var mı?

    // ── Performans Etkisi ──
    pqc_handshake_overhead_ms:    i32,         // PQC'nin getirdiği ek süre
    pqc_bandwidth_overhead_kb:    f32,         // PQC'nin getirdiği ek bant genişliği (KB)
    pqc_client_hello_bloat_bytes: u16,         // ClientHello'daki PQC şişmesi
    estimated_throughput_loss_pct: f32,        // Tahmini throughput kaybı (%)

    // ── Öneriler ──
    recommendations:          Vec<Recommendation>, // Otomatik oluşturulan öneri listesi
    actionable_items:         u8,              // Kaç adet aksiyon alınabilir öneri var?
    needs_immediate_action:   bool,            // Hemen müdahale gerekiyor mu?

    // ── Uyumluluk ──
    nist_sp800_131a_compliant:   bool,
    bsi_tr_02102_compliant:      bool,         // Alman BSI PQC geçiş rehberi
    anssi_pqc_compliant:         bool,         // Fransız ANSSI PQC önerileri
    cnsa_2_compliant:            bool,         // NSA CNSA 2.0 (Commercial National Security)
    etsi_ts_119_312_compliant:   bool,         // ETSI PQC signature suit
}
```

### 11.5 Sihirbaz Rapor Çıktısı (İnteraktif TUI Görünümü)

```
┌──────────────────────────────────────────────────────────────────┐
│  🔐 TLS 1.3 PQC Akıllı Sihirbaz — Rapor                          │
│  Hedef: api.openai.com (104.18.7.21:443)                         │
│  Tarih: 2026-07-23 14:32:17 UTC         Süre: 3.2s               │
├──────────────────────────────────────────────────────────────────┤
│                                                                    │
│  ┌─ Güvenlik Skoru ──────────────────────────────────────────┐   │
│  │                                                            │   │
│  │    🟢 78 / 100  —  İYİ (1 uyarı)                          │   │
│  │                                                            │   │
│  │  ████████████████████████████████████████░░░░░░░░░░        │   │
│  │                                                            │   │
│  └────────────────────────────────────────────────────────────┘   │
│                                                                    │
│  ┌─ KEM / Anahtar Değişim ───────────────────────────────────┐   │
│  │  Client Offered:  [Kyber-1024, Kyber-768, x25519]         │   │
│  │  Server Selected: Kyber-1024 + x25519 (Hybrid) ✅          │   │
│  │  Shared Secret:   256-bit (Klasik) + 256-bit (PQC)        │   │
│  │  Est. KEM Time:   ~1.2ms (Kyber-1024 encapsulation)       │   │
│  └────────────────────────────────────────────────────────────┘   │
│                                                                    │
│  ┌─ Sertifika Zinciri ───────────────────────────────────────┐   │
│  │  🌐 Leaf:    CN=api.openai.com  ── Dilithium5 (ML-DSA-87) │   │
│  │  🔗 Int CA:  CN=Let's Encrypt PQC X1 ── Falcon-1024       │   │
│  │  ⚓ Root:    CN=ISRG Root X2 ── ECDSA-P384                │   │
│  │                                                            │   │
│  │  ⚠️  Uyarı: Root sertifika PQC imzalı değil               │   │
│  │     Risk: Düşük (trust anchor, replace edilmesi zor)       │   │
│  └────────────────────────────────────────────────────────────┘   │
│                                                                    │
│  ┌─ Zafiyet Taraması ────────────────────────────────────────┐   │
│  │  ✅ PQC-001: Güçlü parametre seti (Kyber-1024)             │   │
│  │  ✅ PQC-002: Hybrid KEM kullanılıyor                       │   │
│  │  ✅ PQC-003: TLS 1.3, fallback yok                         │   │
│  │  ⚠️  PQC-004: Root CA PQC imzasız (Bkz. sertifika paneli) │   │
│  │  ✅ PQC-005: Let's Encrypt tarafından imzalanmış           │   │
│  │  ✅ PQC-006: ClientHello boyutu 4.2KB (< 10KB sınır)      │   │
│  │  ✅ PQC-007: PQC handshake overhead ~8ms (iyi)             │   │
│  │  ✅ PQC-008: 0-RTT kullanılmıyor                           │   │
│  │  ✅ PQC-009: KEM negotiation tutarlı                       │   │
│  │  ✅ PQC-010: Sertifika geçerli (87 gün kaldı)              │   │
│  └────────────────────────────────────────────────────────────┘   │
│                                                                    │
│  ┌─ Performans Etkisi ───────────────────────────────────────┐   │
│  │  Klasik TLS 1.3 (x25519):           ~25ms handshake        │   │
│  │  Hybrid TLS 1.3 (PQC + x25519):     ~33ms handshake        │   │
│  │  PQC Overhead:                      +8ms (+32%)            │   │
│  │  Bant Genişliği Overhead:           +2.8KB (Kyber KEM)    │   │
│  │  Tahmini Throughput Kaybı:          < %1 (ihmal edilebilir)│   │
│  └────────────────────────────────────────────────────────────┘   │
│                                                                    │
│  ┌─ Öneriler ────────────────────────────────────────────────┐   │
│  │                                                            │   │
│  │  1. [Orta] Root CA geçişini bekle                           │   │
│  │     ISRG Root X2 PQC sertifikası 2027'de planlanıyor.      │   │
│  │     Şu an için risk düşük — trust anchor manuel doğrulama  │   │
│  │     gerektirir.                                            │   │
│  │                                                            │   │
│  │  2. [Bilgi] Session resumption (PSK) kullanıma alınabilir  │   │
│  │     Tekrarlı bağlantılarda handshake süresi 33ms → ~5ms    │   │
│  │     düşer.                                                 │   │
│  │                                                            │   │
│  └────────────────────────────────────────────────────────────┘   │
│                                                                    │
│  Uyumluluk Durumu:                                                 │
│  🇺🇸 NIST SP 800-131A ✅  🇩🇪 BSI TR-02102 ✅                     │
│  🇫🇷 ANSSI PQC ✅          🇺🇸 NSA CNSA 2.0 ⚠️                   │
│                                                                    │
│  [📄 PDF Export]  [📋 JSON Export]  [🔗 Paylaş]  [🔄 Yeniden Tara] │
│                                                                    │
└──────────────────────────────────────────────────────────────────┘
```

### 11.6 Sihirbaz Modülleri için Gerekli Ek Protokoller

| | # | Protokol | Açıklama |
|---|---|---|---|
| [ ] | 450 | `tls_pqc_wizard_scan` | TLS PQC wizard toplu tarama engine dissector |
| [ ] | 451 | `tls_cert_transparency_v3` | Certificate Transparency v3 (PQC-aware) SCT parser |
| [ ] | 452 | `tls_ech_pqc_interop` | ECH (Encrypted Client Hello) + PQC uyumluluk test proto |
| [ ] | 453 | `tls_key_share_prediction` | Key share negotiation failure tahmin ve rapor proto |
| [ ] | 454 | `tls_downgrade_detector` | TLS downgrade saldırı tespit engine feed |
| [ ] | 455 | `pqc_cve_feed_integration` | NIST NCCoE PQC CVE feed integration proto |
| [ ] | 456 | `tls_perf_benchmark_model` | TLS handshake performans benchmark model verisi |
| [ ] | 457 | `tls_middlebox_detector` | TLS middlebox interference tespit proto |
| [ ] | 458 | `pqc_compliance_checker` | Çoklu standart uyumluluk checker (NIST+BSI+ANSSI+CNSA) |
| [ ] | 459 | `tls_session_resumption_pqc` | PQC-aware session resumption (PSK) analiz proto |

### 11.7 TLS 1.3 PQC Sihirbaz için Gerekli Ek Protokoller Özeti

| Alt Kategori | Protokol Sayısı |
|-------------|-----------------|
| Wizard engine & scan | 4 |
| Vulnerability detection | 3 |
| Performance & compliance | 3 |
| **TOPLAM** | **10** |

---

## 🔢 Güncellenmiş Toplam Protokol Sayısı

| Bölüm | Protokol Sayısı |
|-------|----------------|
| 1. Modern ve Tescilli Bulut / RPC | 85 |
| 2. Modern Oyun ve Gerçek Zamanlı Eğlence | 70 |
| 3. Yapay Zeka ve LLM Trafik | 65 |
| 4. Gelişmiş IoT ve Endüstriyel AI | 65 |
| 5. Gelişmiş Şifreleme ve Kuantum Sonrası (PQC) | 65 |
| 6. AI Traffic Analyzer (ek) | 29 |
| 7. Oyun Motoru Eklenti Sistemi (ek) | 29 |
| 8. PQC İzleme Araçları (ek) | 10 |
| 9. Özelleştirilmiş OPC UA / Endüstriyel Edge (ek) | 20 |
| 10. Proprietary Fieldbus Decode Setleri (ek) | 40 |
| 11. TLS 1.3 PQC Akıllı Sihirbaz (ek) | 10 |
| **GENEL TOPLAM** | **488** |

---

## Uygulama Önerileri

1. **Her kategori için ayrı `impl` branch açılması** — 5 paralel ekip veya sıralı faz olarak ilerlenebilir.
2. **Önce kritik 75 protokol** — MVP olarak en yüksek etkiye sahip protokoller hedeflenmeli.
3. **"AI Traffic Analyzer" Faz 1 öncelikli başlatılmalı** — OpenAI + Anthropic SSE dissector'ları ile temel token analizi ilk 3 haftada çalışır hale gelmeli.
4. **Oyun motoru eklenti sistemi altyapısı kurulmalı** — `plugin.toml` standardı ve community repo yapısı hazırlanmalı, ilk eklenti Unreal Engine Iris olmalı.
5. **PQC Adoption Tracker + Akıllı Sihirbaz** — PQC geçiş süreci kritik olduğu için TLS PQC handshake izleme ve tek tık raporlama en yüksek öncelikli güvenlik özelliği olarak eklenmeli.
6. **Proprietary Fieldbus Vendor Plugin'leri** — Siemens, Rockwell, Beckhoff başta olmak üzere endüstriyel vendor eklentileri için `plugin.toml` standardı genişletilmeli.
7. **OPC UA DPI katmanı** — Endüstriyel kullanıcılar için OPC UA binary detay çözümleme, PubSub NetworkMessage parse ve SecurityPolicy ihlal tespiti sağlanmalı.
8. **Decode Quality Indicator** — Her fieldbus paketi için `decode_coverage_pct` hesaplanmalı, %95 altı plugin güncellemesi önerilmeli.
9. **Test verisi (pcap) toplama** — Her protokol için en az 1 geçerli `.pcap` veya üretici dokümantasyonu referans alınmalı.
10. **Registry'ye `is_modern`, `category`, `vendor` alanları eklenmesi** — Gelecek protokollerin filtrelenebilirliğini ve vendor bazlı gruplanmasını sağlamak için.

---

> **Son Güncelleme:** 2026-07-23
> **Hazırlayan:** Senior Mühendislik Değerlendirmesi — Netscope Protokol Genişletme Stratejisi
> **Toplam:** 488 Protokol (350 temel + 138 "Nasıl Olmalı" katman protokolleri)
> **Doküman Referansı:** `docs/netscope-gelecek-protokolleri.md`
