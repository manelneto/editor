# Lab 1 - Low-Level Security

Os programas escolhidos para investigar foram o `misused_string_fct_taint` (145/146) e o `os_cmd_scope` (155/156), disponibilizados na pasta `Lab1`.

## 145/146 - `misused_string_fct_taint`

O ficheiro `misused_string_fct_taint-bad.c` contém o código abaixo.

```c
#define MAX_SIZE 10

int main(int argc, char *argv[])
{
	char str[MAX_SIZE];
	// Often Misused String Management:
	// Buffer overflow with strcpy function
	if (argc > 1)
		strcpy(str, argv[1]);							/* FLAW */
	return 0;
}
```

Este código contém uma vulnerabilidade de *buffer overflow*, visto que o *input* do utilizador fornecido como primeiro argumento do programa (`argv[1]`) é copiado pela função `strcpy()` para o *array* `str` de tamanho fixo 10, não se verificando se o tamanho do *input* é menor do que o tamanho do *array*, ou seja, permitindo que os limites da memória alocada para o *array* sejam ultrapassados. Como tal, um atacante pode inserir um *input* com comprimento superior ou igual a 10 *bytes* de maneira a escrever indevidamente por cima de memória pertencente à *stack*, realizando um ataque de *buffer overflow* na *stack*.

Efetivamente, as execuções seguintes demonstram a ocorrência de *segmentation faults* quando o *input* fornecido ao programa é suficientemente maior do que o tamanho do *buffer* ao ponto de escrever por cima de zonas de memórias não alocadas ao processo em execução.

![Exemplos de Execução](/Lab1/images/145-example.png)

Assim sendo, existem três CWEs associadas a esta vulnerabilidade:

1. **[CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer](https://cwe.mitre.org/data/definitions/119):** a ausência de verificação do comprimento do *input* em relação ao tamanho do *buffer* permite operações de escrita fora dos limites definidos para o mesmo, tal como demonstra a imagem abaixo.
2. **[CWE-120: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')](https://cwe.mitre.org/data/definitions/120):** o *input* é copiado para o *buffer* sem se verificar se o tamanho do *input* é menor do que o tamanho do *buffer*, possibilitando um *buffer overflow*.
3. **[CWE-121: Stack-based Buffer Overflow](https://cwe.mitre.org/data/definitions/121):** o *buffer* alvo de *overflow* está alocado na *stack*, visto que é uma variável local da função.

![CWE 119](/Lab1/images/145-cwe.png)

Tendo em conta que o código do programa está escrito em C/C++, é adequado correr-se o *scanner* de vulnerabilidades ***Flawfinder***.

![Flawfinder](/Lab1/images/145-flawfinder.png)

Ora, o ***Flawfinder*** deteta corretamente a vulnerabilidade de *buffer overflow* em causa no código exposto, indicando duas das CWEs associadas (CWE-119 e CWE-120), tal como esperado.

Além disso, o ***Snyk Code Checker*** também identifica corretamente a falha no código.

![Snyk Code Checker](/Lab1/images/145-snyk.png)

No entanto, a CWE associada é erradamente identificada como sendo a **[CWE-122: Heap-based Buffer Overflow](https://cwe.mitre.org/data/definitions/122)**, o que não corresponde à realidade, dado que o *buffer* afetado é alocado na *stack* - por ser uma variável local - e não na *heap* - por não existir qualquer chamada à função `malloc()`.

Foi também testado o ***SemGrep***, mas este *scanner* não detetou qualquer vulnerabilidade no programa usando apenas as regras predefinidas.

TODO: *From the error log (or lack thereof), what can you deduct about the scanner's analysis technique?*

O ***Flawfinder*** e o ***Snyk Code Checker*** conseguiram identificar a vulnerabilidade presente. O que aparenta acontecer é que ambos contém uma lista de funções potencialmente inseguras e verificam se estas são utilizadas no programa. Seguidamente são listadas as CWEs associadas (com erro no caso do ***Snyk Code Checker***).
O ***SemGrep*** aparenta no entanto fazer *taint analyses*, sendo essa a razão para não identificar o *strcpy()*.

Para analisar esta vulnerabilidade de *buffer overflow*, foram escolhidas diversas ferramentas dinâmicas e estáticas.

No que toca às ferramentas dinâmicas, escolheu-se utilizar o ***Valgrind*** devido à sua capacidade para detetar erros de memória, em particular vulnerabilidades baseadas em *stack smashing* e *stack overflow*.

Assim, testaram-se alguns exemplos de execução do programa com o ***Valgrind***, quer com *inputs* de tamanho inferior ao do *array* (10), quer com *inputs* capazes de causar uma *segmentation fault*, tal como visto anteriormente.

![Valgrind](/Lab1/images/145-valgrind.png)

No caso de *inputs* com tamanho inferior a 10, o ***Valgrind*** não identificou qualquer problema.

No entanto, ao correr o mesmo comando, mas com *input* de tamanho superior a 10, o ***Valgrind*** foi capaz de identificar a ocorrência de um *stack overflow*. Deste modo, obtêm-se erros indicativos de que ocorreu uma leitura inválida, ou seja, uma tentativa de leitura a partir de um endereço inválido de memória, causando o erro na execução do programa.

De seguida, testou-se a utilização do ***Address Sanitizer***, enquanto detetor de erros de memória em tempo de execução, experimentando-se os vários valores possíveis para a *flag* `fsanitize`, começando pela mais apropriada para este caso, `fsanitize=address`.

![Address Sanitizer fsanitize=address](/Lab1/images/145-addresssanitizer-address-1.png)
![Address Sanitizer fsanitize=address](/Lab1/images/145-addresssanitizer-address-2.png)

Em primeiro lugar, quando o programa foi compilado com a *flag* `fsanitize=address`, o ***Address Sanitizer*** foi capaz de identificar corretamente o *stack buffer overflow*, bem como o endereço em que ocorreu. Esta abordagem funcionou porque a *flag* utilizada ativa o *AddressSanitizer* (ASan) propriamente dito (visto que existem outras categorias de *sanitizers*, a explicar posteriormente) que é projetado para encontrar casos de: *use after free*, *heap buffer overflow*, *stack buffer overflow*, *global buffer overflow*, *use after return*, *use after scope*, *initialization order bugs* e *memory leaks*. Sendo esta vulnerabilidade um caso de *stack buffer overflow*, foi corretamente detetada pelo *Address Sanitizer*. Tecnicamente, o *AddressSanitizer* contém código que permite fazer essas verificações, como *redzones* na *stack* e interseção de acessos a memória. 

Em segundo lugar, compilou-se o programa com a *flag* `fsanitize=leak`.

![Address Sanitizer fsanitize=leak](/Lab1/images/145-addresssanitizer-leak.png)

De forma contrária à anterior, esta compilação já não detetou qualquer erro. Isto acontece porque a *flag* `fsanitize=leak` ativa o *LeakSanitizer*, que é um detetor de *memory leaks* integrado no ***Address Sanitizer***. Efetivamente, como o erro no código não causa um *memory leak*, mas sim um *buffer overflow*, não é esperado que este *sanitizer* acuse o problema, o que se confirmou. Ou seja, o *LeakSanitizer* não está preparado para identificar acessos indevidos à memória, mas sim para testar se existiram alocações de memória que não foram libertadas.

De seguida, utilizou-se a *flag* de compilação `fsanitize=memory`.

![Address Sanitizer fsanitize=memory](/Lab1/images/145-addresssanitizer-memory.png)

Tal como anteriormente, a *flag* `fsanitize=memory` também não acusou qualquer resultado. Este comportamento é esperado porque o *sanitizer* ativo pela *flag* `fsanitize=memory` é o *MemorySanitizer*, cuja função é detetar leituras de memória não inicializada. Ora, como a vulnerabilidade presente no código consiste num erro de escrita em memória e não num erro de leitura, encontra-se fora do âmbito do *MemorySanitizer*, que apenas está preparado para identificar no programa analisado se são lidos conteúdos a partir de endereços de memória não inicializada.

Por último, a compilação do programa foi feita com a *flag* `fsnatize=undefined`.

![Address Sanitizer fsanitize=undefined](/Lab1/images/145-addresssanitizer-undefined-1.png)
![Address Sanitizer fsanitize=undefined](/Lab1/images/145-addresssanitizer-undefined-2.png)

Desta vez, o ***Address Sanitizer*** identificou adequadamente o comportamento indefinido do programa para *inputs* a partir de um certo tamanho. Isto deve-se ao comportamento do *UndefinedBehaviorSanitizer* (UBSan), que modifica o programa em tempo de compilação para detetar diversos tipos de comportamento indefinido durante a execução do programa. Como um *buffer overflow* - escrita para um *array* num *offset* para além do tamanho do mesmo - é um exemplo de comportamento indefinido na especificação da linguagem C, foi corretamente assinalado pela ferramenta. Em particular, o *UndefinedBehaviorSanitizer* usa várias ferramentas dos *sanitizers* anteriores, inclusive a que funcionou.

As ferramentas dinâmicas ***Taintgrind*** e ***Clang Data Flow Sanitizer*** não foram executadas por não serem adequadas à deteção da vulnerabilidade em questão, visto que o seu propósito consiste em identificar o fluxo de informação do programa, em particular o destino de *inputs* sensíveis, o que não era o pretendido neste caso. Além disso, a ferramenta ***TIMECOP*** também não foi utilizada, por não existir qualquer relação entre o programa vulnerável apresentado e *timing attacks*, pelo que não é pertinente efetuar *constant-time analysis*.

Passando para a análise estática do programa, correram-se as ferramentas mais interessantes para o efeito.

Inicialmente, a ferramenta ***Scan-build*** foi executada por se tratar de uma solução para detetar erros de programação em programas escritos em C/C++, como é o caso.

![Scan-build](/Lab1/images/145-scanbuild.png)

Efetivamente, o ***Scan-build*** alertou corretamente para o *bug* encontrado no código, em particular na chamada à função `strcpy()`. Esta deteção funcionou porque o ***Scan-build*** emite um aviso/alerta para qualquer utilização de `strcpy()`, mesmo que não constitua uma vulnerabilidade. Neste caso, é realmente uma chamada potencialmente insegura, por não se verificarem os limites do *input*.

Posteriormente, foi executado a analisador estático ***IKOS*** contra o mesmo código C/C++ para investigar a segurança do programa.

![IKOS](/Lab1/images/145-ikos.png)

O ***IKOS*** identificou corretamente o programa como potencialmente inseguro por quatro razões. As duas primeiras razões referem-se à possível utilização do valor de `argv[1]` sem ter sido inicializado, podendo, por isso, ser nulo. No entanto, estes dois casos não se aplicam na prática, porque, ao verificar-se que `argc > 1`, garante-se que `argv[1]` contém algum valor, nomeadamente o *input* fornecido pelo utilizador ao programa. Após isso, surge mais um aviso relativamente ao conteúdo de `argv[1]` enquanto acesso a memória, mas também não é esse o objeto principal da análise de vulnerabilidades. Finalmente, o último aviso da ferramenta salienta a possibilidade da ocorrência de um *buffer overflow*, como é o caso. O ***IKOS*** conseguiu identificar esta vulnerabilidade por causa da maneira como este funciona. O ***IKOS*** contém uma lista de funções potêncialmente inseguras e alerta se alguma dessas funções é utilizada, como é o caso de `strcpy()`, tal como os passos para evitar essa vulnerabilidade.

A ferramenta ***Frama-C*** não foi testada, por ser especialmente focada em programas de tamanho industrial escritos em ISO C99, o que não se aplica nesta situação em particular, dada a simplicidade do código. Por já terem sido experimentadas outras ferramentas estáticas, descartou-se a utilização de ***Smack***. Além disto, não sendo este um caso para o qual faz sentido realizar *constant-time analysis*, não se correu ***ctverif***.

Por último, foi executada a ferramenta ***infer*** para experimentar mais uma análise estática para erros de memória, de forma semelhante a ***scan-build***.

![infer](/Lab1/images/145-infer.png)

Relativamente às ferramentas dinâmicas, tanto o ***Valgrind*** como o ***Address Sanitizer*** identificaram corretamente o problema. Damos primazia, no entanto, ao ***Address Sanitizer*** devido à informação extra que é providenciada como o endereço onde o *stack buffer overflow* ocorreu quando ultilizada a flag correta.
Tanto o ***IKOS*** como o ***Scan-build*** identificaram o comando `strcpy()` como potencialmente perigoso, mas não oferece mais informação por não ter contexto extra. O ***infer*** não identificou nenhum problema. Podemos então chegar à conclusão que a análise estática deste tipo de problemas não é particularmente útil, não dizendo nada específico em relação ao programa.

## 155/156 - `os_cmd_scope`

O ficheiro `os_cmd_scope-bad.c` contém o código abaixo.

```c
#define SIZE_CMD 14
const char cmd[SIZE_CMD] = "/usr/bin/cat ";

void runCommand(char *str) 
{
	if(system(str) < 0)							        /* FLAW */
		fprintf(stderr, "system() failed");
}

int main(int argc, char *argv[])
{
	char sys[512];
	char buff[512];
	if (fgets(buff,512 - SIZE_CMD,stdin))
	{
		strcpy(sys, cmd);
		strcat(sys, buff);
		runCommand(sys);
	}
	return 0;
}
```

Este código contém uma vulnerabilidade de *command injection*, visto que o *input* do utilizador obtido do *standard input* (`stdin`) para o *array* `buff` é concatenado pela função `strcat()` no *array* `sys`, que contém previamente o valor da variável `cmd`, ou seja, o comando `/usr/bin/cat`, que será executado pelo sistema através da chamada à função `system()`. Como tal, um atacante pode inserir um *input* malicioso que, após a execução do comando `/usr/bin/cat ...`, execute outro comando arbitrário, realizando um ataque de *command injection*.

Efetivamente, as execuções seguintes demonstram a execução de diferentes comandos fornecidos como *input* ao programa, contornando o seu propósito de executar unicamente `cat` e concretizando, assim, um ataque de *command injection*.

![Exemplos de Execução](/Lab1/images/155-example.png)

Assim sendo, existe uma principal CWE associada a esta vulnerabilidade:

1. **[CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')](https://cwe.mitre.org/data/definitions/78):** o programa constrói parte de um comando do sistema operativo utilizando *input* externo fornecido pelo utilizador, mas sem neutralizar os elementos que podem modificar o comportamento esperado do comando a executar, tal como demonstra a imagem abaixo.

![CWE 78](/Lab1/images/155-cwe.png)

Note-se que, dadas as chamadas às funções `strcpy()` e `strcat()` sem a devida validação do tamanho do *input*, podem ainda ser concretizados ataques de *buffer overflow*, tal como explicado anteriormente, estando estes casos igualmente associados às CWEs anteriores, pelo que estas não serão novamente exploradas.

Como o código do programa está também escrito em C/C++, pode correr-se o *scanner* de vulnerabilidades ***Flawfinder***.

![Flawfinder](/Lab1/images/155-flawfinder.png)

De facto, o ***Flawfinder*** deteta corretamente a vulnerabilidade de *command injection* em causa no código exposto, identificando a CWE associada (CWE-78), tal como seria expectável. A par disso, esta ferramenta alerta ainda para as restantes CWEs já abordadas (CWE-119 e CWE-120) relacionadas com os possível ataques de *buffer overflow*.

De forma análoga à anterior, testou-se também o ***Snyk Code Checker*** para este caso.

![Snyk Code Checker](/Lab1/images/155-snyk.png)

Ora, o ***Snyk Code Checker*** também identifica corretamente a falha no código e a CWE associada.

Finalmente, foi igualmente executado o ***SemGrep***.

![SemGrep](/Lab1/images/155-semgrep-1.png)

![SemGrep](/Lab1/images/155-semgrep-2.png)

Para além de realçar a vulnerabilidade de *command injection* devido à ausência de neutralização do *input*, o ***SemGrep*** alerta para a chamada à função `system()`, que deve ser evitada precisamente por permitir a execução de múltiplos comandos de forma eventualmente indevida. Assim sendo, a ferramenta sugere a utilização de outras interfaces mais restritivas, como `execve()`. Em ambas as situações, a CWE-78 é corretamente identificada.
