# VaultSalt — Contêiner Seguro de Arquivos (.sf8aj)

![Segurança](https://img.shields.io/badge/Segurança-12%20chars%3A%20171M%20anos%20%7C%2016%20chars%3A%2014Q%20anos%20%7C%2024%20chars%3A%20Incalculável-brightgreen)

VaultSalt é uma ferramenta de **criptografia local de arquivos**, transformando qualquer arquivo em um contêiner seguro com extensão `.sf8aj`.  
A proteção é baseada em **senha do usuário**, derivada com Argon2id e criptografada usando ChaCha20-Poly1305 (AEAD).  
Cada arquivo tem **salt único**, metadados criptografados e padding adaptativo, garantindo máxima privacidade.

---

## 🔐 Descrição do Projeto

VaultSalt permite:
- **Proteger nome, metadados e conteúdo** com criptografia robusta.
- **Camuflar tamanho real do arquivo** com padding adaptativo.
- **Armazenar arquivos em segurança**, mantendo-os inacessíveis sem a senha correta.

Ideal para **backups locais, compartilhamento seguro e armazenamento offline** de arquivos sensíveis.

---

## ⚙️ Como Funciona

1. **Entrada do usuário**
   - Forneça um arquivo e uma senha.
   - Senha mínima: 12 caracteres (deve incluir maiúscula, minúscula, número e símbolo).

2. **Geração de Salt Aleatório**
   - Cada arquivo recebe **16 bytes de salt** aleatório.
   - Salt é armazenado no cabeçalho do arquivo `.sf8aj`.

3. **Derivação de Chave**
   - Argon2id (memory-hard KDF) transforma a senha em chave de 256 bits.
   - Parâmetros padrão:
     - `time_cost = 4`
     - `memory_cost = 512 MiB`
     - `parallelism = 4`
     - `hash_len = 32 bytes`
   - Cada arquivo tem chave independente, mesmo que a mesma senha seja usada.

4. **Criptografia AEAD**
   - ChaCha20-Poly1305 cifra e autentica:
     - Nome do arquivo
     - Metadados (tamanho, padding, algoritmo)
     - Payload (conteúdo real, comprimido e com padding)
   - Nonces aleatórios garantem segurança única por bloco.

5. **Compressão + Padding**
   - zlib/zstandard para comprimir conteúdo.
   - Padding adaptativo para múltiplos de 1 MiB, ofuscando o tamanho real.

6. **Saída**
   - Arquivo `.sf8aj` com nome aleatório (UUID) salvo em `secure_storage/`.

---

## 🔑 Senhas — recomendações detalhadas

- **Mínimo:** 12 caracteres  
- **Recomendado:** 16–32 caracteres ou uma passphrase legível (>24 chars)  

### Exemplo de senha básica (12 caracteres)
Seguindo o padrão do sistema:

- Pelo menos 1 maiúscula  
- Pelo menos 1 minúscula  
- Pelo menos 1 número  
- Pelo menos 1 símbolo  

Estimativa de tempo para força bruta (10⁸ tentativas por segundo):

- **12 caracteres (mínimo válido):** ~171 milhões de anos → mais velho que os dinossauros  
- **16 caracteres (forte):** ~14 quadrilhões de anos → 1 milhão de vezes a idade do Universo  
- **24 caracteres (extrema):** ~9,3×10³¹ anos → praticamente impossível, além do tempo de qualquer escala humana ou universal  

> Mesmo considerando ataques quânticos teóricos (Grover), senhas de 16+ caracteres continuam extremamente seguras.


