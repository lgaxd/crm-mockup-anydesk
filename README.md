# 🖥️ AnyDesk CRM Mockup  
**Painel de Gestão de Clientes e Sessões AnyDesk**  

Este projeto é um **CRM mockado e integrável** desenvolvido para gerenciar **clientes**, **sessões** e **informações de acesso** do **AnyDesk**.  
Ele foi criado para **demonstrações, testes e apresentações** (como o webinar de parceiros), permitindo alternar facilmente entre **modo real** (com autenticação HMAC) e **modo simulado** com dados mock.

---

## 🎯 Objetivo  
O **AnyDesk CRM Mockup** foi desenvolvido para facilitar a **visualização**, **gerenciamento** e **análise** de ambientes de suporte remoto, permitindo que equipes técnicas, gerentes e parceiros acompanhem clientes e sessões de forma prática e centralizada.  

Ele integra com a **API do AnyDesk** para fornecer dados reais (quando disponíveis) ou usa um **modo mock** para ambientes de teste e demonstração.

---

## 🚀 Principais Features  

### 🔹 Gestão de Clientes  
- Listagem de todos os clientes conectados à licença.  
- Visualização de detalhes do cliente:  
  - **Alias** configurado  
  - **Versão do cliente**  
  - **Status online/offline**  
  - **Tempo online acumulado**  
  - Últimas sessões associadas.  
- Alteração de **alias** ou remoção completa.

---

### 🔹 Gestão de Sessões  
- Listagem de sessões ativas e encerradas.  
- Visualização detalhada de uma sessão:
  - **Participantes** (origem e destino).  
  - **Status atual** (ativa/encerrada).  
  - **Duração** da sessão.  
  - **Comentários** associados.
- Encerramento manual de sessões ativas.
- Inclusão ou edição de comentários para qualquer sessão.

---

### 🔹 Modos de Operação  

O projeto foi desenvolvido para funcionar em dois cenários distintos:  

| **Modo**   | **Descrição**                                                     | **Indicado para**                  |
|-----------|-----------------------------------------------------------------|----------------------------------|
| **Real** | Integra com a **API oficial** do AnyDesk utilizando autenticação **HMAC-SHA1**. | Ambientes com credenciais válidas. |
| **Mock** | Utiliza dados simulados para clientes e sessões.                  | Demonstrações, treinamentos e testes. |
| **Auto** | Usa **Real** se houver credenciais configuradas, caso contrário, ativa **Mock**. | Configuração padrão recomendada. |

---

### 🔹 Recursos Técnicos  
- **Integração com API REST do AnyDesk** com autenticação **HMAC-SHA1**.  
- Assinatura segura incluindo:  
  - **HTTP Method**  
  - **Resource Path + Query**  
  - **Timestamp**  
  - **SHA1 do corpo da requisição**.  
- Fallback automático para **mock** em caso de falhas.  
- Templates prontos e responsivos com **Flask + Jinja2**.  
- Estrutura limpa, organizada e escalável.

---

## 📊 Público-Alvo  

O projeto foi desenhado para **times de TI, gerentes de suporte, integradores e parceiros comerciais** que desejam:  
- Demonstrar o potencial da **API do AnyDesk**.  
- Visualizar de forma clara clientes e sessões ativas.  
- Criar **provas de conceito** para integração com outros sistemas.  
- Treinar equipes de suporte remoto com **ambiente simulado**.

---

## 🛠️ Estrutura de Rotas  

| **Rota**                    | **Método** | **Descrição**                               |
|---------------------------|------------|-------------------------------------------|
| `/`                       | GET        | Redireciona para a listagem de clientes. |
| `/users`                 | GET        | Lista todos os clientes. |
| `/clients/<cid>`         | GET        | Detalhes de um cliente específico. |
| `/clients/<cid>/alias`   | POST       | Altera o alias de um cliente. |
| `/clients/<cid>/alias/remove` | POST | Remove o alias de um cliente. |
| `/sessions`             | GET        | Lista todas as sessões. |
| `/sessions/<sid>`       | GET        | Detalhes de uma sessão específica. |
| `/sessions/<sid>/close` | POST      | Encerra uma sessão ativa. |
| `/sessions/<sid>/comment` | POST   | Atualiza ou remove o comentário de uma sessão. |

---

## 📌 Diferenciais para Demonstração  

- **100% funcional mesmo sem credenciais reais**.  
- **Dados mock** prontos para **webinars** e **apresentações comerciais**.  
- Interface simples, responsiva e amigável.  
- Possibilidade de alternar dinamicamente entre **modo real** e **modo simulado**.

---
