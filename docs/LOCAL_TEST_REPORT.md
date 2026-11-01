# Relatório de testes locais — v0.1.0

Ambiente de execução: Python 3.13, `unittest` da biblioteca padrão e servidor HTTP temporário na interface de loopback. O escopo dos testes não executa ataques ou consultas contra serviços de terceiros.

| Verificação | Resultado |
| --- | --- |
| Suíte de testes (`python -m unittest discover -s tests -q`) | **56/56 PASS** |
| Análise sintática (`python -m compileall -q src`) | PASS |
| Instalação local editável com setuptools | PASS |
| Build do wheel (`pip wheel . --no-build-isolation --no-deps`) | PASS |
| CLI `circuitlock --help` | PASS |
| `pip check` global da imagem | **Conflito pré-existente de moviepy/Pillow**; não relacionado às dependências runtime (zero) deste pacote |
| GitHub Actions multiplataforma | **Pendente de criação/publicação do novo repositório** |

**Limites:** testes de TLS usam inspeção da configuração de contexto (`check_hostname` e `CERT_REQUIRED`); handshake real com certificado de CA descartável e simulação completa de DNS malicioso de produção permanecem fora do escopo desta versão.
