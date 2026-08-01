# Netscope Yapay Zeka (AI) ve LLM Ağ Analitiği Özellikleri

Netscope, geleneksel ağ analizörlerinin (Wireshark vb.) aksine, günümüzün modern veri merkezleri ve kurumsal ağlarında yoğunlaşan **Yapay Zeka (AI), Büyük Dil Modelleri (LLM) ve GPU Küme (Cluster) Trafiğini** analiz etmek, izlemek ve güvenliğini sağlamak amacıyla tasarlanmış gelişmiş yapay zeka odaklı analiz yeteneklerine sahiptir.

Bu dokümanda, Netscope'un çekirdeğinde ([`ai_traffic.rs`](file:///c:/Users/efe/Desktop/netscope/crates/core/src/ai_traffic.rs), [`llm_analytics.rs`](file:///c:/Users/efe/Desktop/netscope/crates/core/src/llm_analytics.rs) ve [`pqc_analytics.rs`](file:///c:/Users/efe/Desktop/netscope/crates/core/src/pqc_analytics.rs)) yer alan yapay zeka tabanlı özellikleri incelenmektedir.

---

## 1. AI ve LLM Protokol Çözümleyicileri (AI Traffic Dissectors)

Netscope, popüler yapay zeka sağlayıcılarının ve API ağ geçitlerinin (AI Gateways) protokollerini doğrudan tanır ve paket gövdesini (payload) çözümleyerek anlamlı verilere dönüştürür (Bkz: [`registry.rs`](file:///c:/Users/efe/Desktop/netscope/crates/core/src/registry.rs)):

*   **Lider LLM Servisleri:** OpenAI (Chat, Realtime, Batch, Streaming), Anthropic (Claude Messages, ToolUse, Constitutional), Google Gemini (Bidirectional WS, Rest Stream, AI Studio WS), DeepSeek, Mistral, Groq, xAI (Grok), AWS Bedrock.
*   **AI Gateway ve Observability Ağ Geçitleri:** Cloudflare AI Gateway, Kong AI Gateway, LiteLLM Proxy, Portkey Gateway, Helicone, Langfuse, MLflow Gateway, Arize Phoenix.
*   **Açık Kaynak Çıkarım (Inference) Sunucuları:** vLLM, HuggingFace TGI, NVIDIA Triton Inference Server, Sglang Radix Cache.

---

## 2. LLM Performans Telemetrisi ve Metrikleri

Netscope, ağ üzerinden akan LLM API istek ve yanıt paketlerini birleştirerek gerçek zamanlı performans analizi yapar:

*   **TTFT (Time to First Token - İlk Karakter Süresi):** İsteğin gönderilmesi ile modelin ilk yanıt token'ını (karakter grubunu) ağ üzerinden göndermesi arasında geçen süreyi hesaplar.
*   **TPOT (Time Per Output Token - Token Başına Çıkış Süresi):** Modelin karakterleri ne kadar hızlı ürettiğini ağ paketlerinin varış sürelerinden analiz eder.
*   **TPS (Tokens Per Second - Saniyelik Token Hızı):** Canlı akış (streaming) sırasında saniyede iletilen ortalama token hızını takip eder.
*   **Otomatik Maliyet Tahmini (USD Cost Estimation):** Modellerin güncel fiyat listelerini (OpenAI GPT-4o, Claude 3 Opus, Gemini 1.5 Pro vb.) kullanarak, ağ paketlerindeki prompt/completion token sayılarını çarpıp harcanan bütçeyi gerçek zamanlı dolar cinsinden hesaplar.

---

## 3. Yapay Zeka Tabanlı Anomali Tespit Motoru (AI Anomaly Alerts)

Netscope çekirdeği, toplanan LLM metriklerini sürekli izleyerek ağ seviyesinde şu anomaliler için otomatik alarmlar üretir:

- [x] **Gecikme (TTFT) Anomalisi:** Modelin yanıt vermeye başlama süresi (TTFT) **500 ms** değerini aşarsa, kullanıcı deneyimi yavaşlığı nedeniyle alarm üretilir.
- [x] **Üretim (TPOT / TPS) Anomalisi:** Token üretme hızı saniyede **20 token'ın altına** düşerse veya token başına süre **80 ms** üzerine çıkarsa (model tıkanması/yavaşlama) alarm tetiklenir.
- [x] **Maliyet (Bill Shock) Anomalisi:** Tek bir API isteğinin maliyeti **0.10 USD** sınırını aşarsa, büyük veri sızıntılarını veya sonsuz döngüye giren promptları engellemek için maliyet aşım alarmı verilir.
- [x] **Limit Aşımı (Rate Limit) Anomalisi:** Ağdan dönen HTTP 429 (Too Many Requests) hata paketleri anında SOC uyarısına dönüştürülür.
- [x] **Akış Bölünmesi (Incomplete Stream) Anomalisi:** Streaming yanıtı başarıyla bitmeden (`finish_reason != "stop"`) bağlantı koparsa ağ kesintisi alarmı üretilir.

---

## 4. Yapay Zeka Altyapısı (GPU Küme) Protokolleri (AI Infra Dissectors)

Büyük yapay zeka modellerini eğiten ve çalıştıran arka uç GPU kümelerinin iç trafiğini analiz etmek için geliştirilmiş özel protokol destekleri mevcuttur:

*   **GPU Kolektif İletişimi (Collective Comm):** NVIDIA NCCL (Broadcast, AllGather) protokolleri ve DeepSpeed (GlooTCP) trafiği izlenerek GPU'lar arası senkronizasyon gecikmeleri ölçülür.
*   **Model Dağıtımı & Sharding:** PyTorch RPC Framework ve JAX Pjit Sharding trafiği izlenerek model parametrelerinin GPU'lara dağıtım verimliliği incelenir.
*   **Vektör Veritabanları (Vector DBs):** Pinecone, Weaviate, Qdrant ve Milvus veritabanlarının gRPC/Raft replikasyon ve sorgu protokolleri analiz edilerek RAG (Retrieval-Augmented Generation) altyapısının performansı ölçülür.
*   **Tokenizers:** Tiktoken, SentencePiece ve HuggingFace Tokenizer konfigürasyon dosyalarının ağdan aktarımı izlenir.

---

## 5. Post-Quantum Kriptografi (PQC) Analitiği

Kuantum bilgisayarlarının gelecekte şifrelenmiş trafiği çözebilme riskine karşı ağ güvenliğini test eder:
*   Yapay zeka ağ geçitleri ve sunucularla yapılan SSL/TLS el sıkışmalarını inceleyerek, kuantum güvenli algoritmaların (Kyber / ML-KEM ve Dilithium / ML-DSA) kullanılıp kullanılmadığını analiz eder ve kurumsal PQC uyumluluk skorunu hesaplar ([`pqc_analytics.rs`](file:///c:/Users/efe/Desktop/netscope/crates/core/src/pqc_analytics.rs)).
