# ThrottleStop-PPL-Bypass---x64-Assembly
 Exploit de segurança ofensivo voltado para contornar proteções do Windows e comprometer o processo lsass.exe.

 Passo a Passo de Seu Funcionamento:
1. Descoberta do processo alvo
Enumera os processos em execução para encontrar o PID do lsass.exe (Local Security Authority Subsystem — responsável por armazenar credenciais do Windows).
2. Instalação de um driver malicioso
Usa o Service Control Manager para registrar e iniciar um driver de kernel (a.sys) chamado "ThrottleStop", explorando o nome de uma ferramenta legítima de gerenciamento de CPU como disfarce.
3. Obtenção de leitura/escrita no kernel
Abre um handle para o driver via CreateFileA e usa DeviceIoControl (IOCTL 0x8000645C) para obter primitivas de leitura e escrita arbitrária na memória do kernel.
4. Localização do EPROCESS do LSASS
Lê o símbolo PsInitialSystemProcess do ntoskrnl.exe e percorre a lista encadeada de estruturas EPROCESS no kernel até encontrar a entrada correspondente ao PID do lsass.exe.
5. Remoção das proteções PPL
Zera os campos Protection (offset 0x6CA) e SignatureLevel (offset 0x6C8) na estrutura EPROCESS do LSASS, desabilitando o Protected Process Light (PPL) — mecanismo que impede acesso ao processo por ferramentas não assinadas.
6. Injeção de DLL
Chama AddSecurityPackageA apontando para ntssp.dll — uma técnica conhecida de injeção no contexto do LSASS para extrair credenciais (hashes, senhas em texto claro, tickets Kerberos etc.).

Um mapa do Fluxograma do funcionamento do Exploit:

<img width="1604" height="9282" alt="MAP" src="https://github.com/user-attachments/assets/4281d68d-494f-4110-bc72-1a631682971f" />
