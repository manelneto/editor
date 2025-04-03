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

Este código apresenta uma vulnerabilidade de *buffer overflow*, visto que o *input* do utilizador fornecido como primeiro argumento do programa (`argv[1]`) é copiado pela função `strcpy()` para o *array* `str` de tamanho fixo 10, não se verificando se o tamanho do *input* é menor do que o tamanho do *array*, ou seja, permitindo que os limites da memória alocada para o *array* `str` sejam ultrapassados. Como tal, um atacante pode inserir um *input* com comprimento superior a 10 *bytes* de maneira a escrever indevidamente por cima de memória pertencente à *stack*, realizando um ataque de *buffer overflow* na *stack*.

Efetivamente, as execuções seguintes demonstram a ocorrência de *segmentation faults* quando o *input* fornecido ao programa é suficientemente maior do que o tamanho do *buffer* ao ponto de escrever por cima de zonas de memórias não alocadas ao processo em execução.

![Exemplos de Execução](/Lab1/images/145-example.png)

Assim sendo, existem três CWEs associadas a esta vulnerabilidade:

1. **[CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer](https://cwe.mitre.org/data/definitions/119):** a ausência de verificação do comprimento do *input* em relação ao tamanho do *buffer* permite operações de escrita fora dos limites definidos para o mesmo, tal como demonstra a imagem abaixo.
2. **[CWE-120: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')](https://cwe.mitre.org/data/definitions/120):** o *input* é copiado para o *buffer* sem se verificar se o tamanho do *input* é menor do que o tamanho do *buffer*, possibilitando um *buffer overflow*.
3. **[CWE-121: Stack-based Buffer Overflow](https://cwe.mitre.org/data/definitions/121):** o *buffer* alvo de *overflow* está alocado na *stack*, visto que é uma variável local da função.

![CWE 119](/Lab1/images/145-cwe.png)

O programa `misused_string_fct_taint-good.c` apresenta o código abaixo, com a vulnerabilidade já corrigida.

```c
#define MAX_SIZE 10

int main(int argc, char *argv[])
{
	char str[MAX_SIZE];
	// Often Misused String Management:
	// Buffer overflow with strcpy function
	if (argc > 1)
	{
		strncpy(str, argv[1], MAX_SIZE - 1);					/* FIX */
		str[MAX_SIZE - 1] = '\0';
	}
	return 0;
}
```

Neste caso, a utilização de `strncpy()` - em vez de `strcpy()` - com o número de *bytes* a copiar limitado a `MAX_SIZE - 1` garante que não é possível explorar a falha de *buffer overflow* anteriormente exposta.

### *Vulnerability Scanners*

Tendo em conta que o código do programa está escrito em C/C++, é adequado correr-se o *scanner* de vulnerabilidades ***Flawfinder***.

![Flawfinder](/Lab1/images/145-flawfinder.png)

Ora, o ***Flawfinder*** deteta corretamente a vulnerabilidade de *buffer overflow* em causa no código exposto, indicando duas das CWEs associadas (CWE-119 e CWE-120), tal como esperado.

Além disso, o ***Snyk Code Checker*** também identifica corretamente a falha no código.

![Snyk Code Checker](/Lab1/images/145-snyk.png)

No entanto, a CWE associada é erradamente identificada como sendo a **[CWE-122: Heap-based Buffer Overflow](https://cwe.mitre.org/data/definitions/122)**, o que não corresponde à realidade, dado que o *buffer* afetado é alocado na *stack* - por ser uma variável local - e não na *heap* - por não existir qualquer chamada à função `malloc()`.

Foi também testado o ***SemGrep***, mas este *scanner* não detetou qualquer vulnerabilidade no programa, usando apenas as regras predefinidas.

Em suma, o ***Flawfinder*** e o ***Snyk Code Checker*** conseguiram identificar a vulnerabilidade presente. O que aparenta acontecer é que ambos contêm uma lista de funções potencialmente inseguras e verificam se estas são utilizadas no programa. Além disso, o ***Snyk Code Checker*** demonstrou também realizar *taint analysis*, detetando que o *input* do utilizador proveniente de `argv[1]` (*source*) flui até `strcpy()` (*sink*), sem ser sanitizado, o que representa uma falha de segurança. Posteriormente, são listadas as CWEs associadas (com erro no caso do ***Snyk Code Checker***). O ***SemGrep*** aparenta, no entanto, fazer apenas *taint analysis*, sendo essa a razão para não identificar a vulnerabilidade de *buffer overflow* no  `strcpy()`.

### Ferramentas de Análise

Para analisar esta vulnerabilidade de *buffer overflow*, foram escolhidas diversas ferramentas dinâmicas e estáticas.

#### Análise Dinâmica

No que toca às ferramentas dinâmicas, escolheu-se utilizar o ***Valgrind*** devido à sua capacidade para detetar erros de memória, em particular vulnerabilidades baseadas em *stack smashing* e *stack overflow*.

Assim, testaram-se alguns exemplos de execução do programa com o ***Valgrind***, quer com *inputs* de tamanho inferior ao do *array* (10), quer com *inputs* capazes de causar uma *segmentation fault*, tal como visto anteriormente.

![Valgrind](/Lab1/images/145-valgrind.png)

No caso de *inputs* com tamanho inferior a 10, o ***Valgrind*** não identificou qualquer problema.

No entanto, ao correr o mesmo comando, mas com *input* de tamanho superior a 10, o ***Valgrind*** foi capaz de identificar a ocorrência de um *stack overflow*. Deste modo, obtêm-se erros indicativos de que ocorreu uma leitura inválida, ou seja, uma tentativa de leitura a partir de um endereço inválido de memória, causando o erro na execução do programa.

De seguida, testou-se a utilização do ***Address Sanitizer*** enquanto detetor de erros de memória em tempo de execução, experimentando-se os vários valores possíveis para a *flag* `fsanitize`, começando pela mais apropriada para este caso, `fsanitize=address`.

![Address Sanitizer fsanitize=address](/Lab1/images/145-addresssanitizer-address-1.png)
![Address Sanitizer fsanitize=address](/Lab1/images/145-addresssanitizer-address-2.png)

Em primeiro lugar, quando o programa foi compilado com a *flag* `fsanitize=address`, o ***Address Sanitizer*** foi capaz de identificar corretamente o *stack buffer overflow*, bem como o endereço em que ocorreu. Esta abordagem funcionou porque a *flag* utilizada ativa o *AddressSanitizer* (ASan) propriamente dito - visto que existem outras categorias de *sanitizers*, a explicar posteriormente - que é projetado para encontrar casos de *use after free*, *heap buffer overflow*, *stack buffer overflow*, *global buffer overflow*, *use after return*, *use after scope*, *initialization order bugs* e *memory leaks*. Sendo esta vulnerabilidade um caso de *stack buffer overflow*, foi corretamente detetada pelo *Address Sanitizer*. Tecnicamente, o *AddressSanitizer* contém código que permite fazer essas verificações, como *redzones* na *stack* e interseção de acessos a memória. 

Em segundo lugar, compilou-se o programa com a *flag* `fsanitize=leak`.

![Address Sanitizer fsanitize=leak](/Lab1/images/145-addresssanitizer-leak.png)

De forma contrária à anterior, esta compilação já não detetou qualquer erro. Isto acontece porque a *flag* `fsanitize=leak` ativa o *LeakSanitizer*, que é um detetor de *memory leaks* integrado no ***Address Sanitizer***. Efetivamente, como o erro no código não causa um *memory leak*, mas sim um *buffer overflow*, não é esperado que este *sanitizer* acuse o problema, o que se confirmou. Ou seja, o *LeakSanitizer* não está preparado para identificar acessos indevidos à memória, mas sim para testar se existiram alocações de memória que não foram libertadas.

De seguida, utilizou-se a *flag* de compilação `fsanitize=memory`.

![Address Sanitizer fsanitize=memory](/Lab1/images/145-addresssanitizer-memory.png)

Tal como anteriormente, a *flag* `fsanitize=memory` também não acusou qualquer resultado. Este comportamento é esperado porque o *sanitizer* ativo pela *flag* `fsanitize=memory` é o *MemorySanitizer*, cuja função é detetar leituras de memória não inicializada. Ora, como a vulnerabilidade presente no código consiste num erro de escrita em memória e não num erro de leitura, encontra-se fora do âmbito do *MemorySanitizer*, que apenas está preparado para identificar se são lidos conteúdos a partir de endereços de memória não inicializada.

Por último, a compilação do programa foi feita com a *flag* `fsanitize=undefined`.

![Address Sanitizer fsanitize=undefined](/Lab1/images/145-addresssanitizer-undefined-1.png)
![Address Sanitizer fsanitize=undefined](/Lab1/images/145-addresssanitizer-undefined-2.png)

Desta vez, o ***Address Sanitizer*** identificou adequadamente o comportamento indefinido do programa para *inputs* a partir de um certo tamanho. Isto deve-se ao comportamento do *UndefinedBehaviorSanitizer* (UBSan), que modifica o programa em tempo de compilação para detetar diversos tipos de comportamento indefinido durante a execução do programa. Como um *buffer overflow* - escrita para um *array* num *offset* para além do tamanho do mesmo - é um exemplo de comportamento indefinido na especificação da linguagem C, foi corretamente assinalado pela ferramenta. Em particular, o *UndefinedBehaviorSanitizer* usa várias ferramentas dos *sanitizers* anteriores, inclusive a que resultou inicialmente.

As ferramentas dinâmicas ***Taintgrind*** e ***Clang Data Flow Sanitizer*** não foram executadas por não serem adequadas à deteção da vulnerabilidade em questão, visto que o seu propósito consiste em identificar o fluxo de informação do programa, em particular o destino de *inputs* sensíveis, o que não era o pretendido neste caso. Além disso, a ferramenta ***TIMECOP*** também não foi utilizada, por não existir qualquer relação entre o programa vulnerável apresentado e *timing attacks*, pelo que não é pertinente efetuar *constant-time analysis*.

#### Análise Estática

Passando para a análise estática do programa, correram-se as ferramentas mais interessantes para o efeito.

Inicialmente, a ferramenta ***scan-build*** foi executada por se tratar de uma solução para detetar erros de programação em programas escritos em C/C++, como é o caso.

![scan-build](/Lab1/images/145-scanbuild.png)

Efetivamente, o ***scan-build*** alertou corretamente para o *bug* encontrado no código, em particular na chamada à função `strcpy()`. Esta deteção funcionou porque o ***scan-build*** emite um aviso/alerta para qualquer utilização de `strcpy()`, mesmo que não constitua uma vulnerabilidade. Neste caso, é realmente uma chamada potencialmente insegura, por não se verificarem os limites do *input*.

Posteriormente, foi executado o analisador estático ***IKOS*** contra o mesmo código C/C++ para investigar a segurança do programa.

![IKOS](/Lab1/images/145-ikos.png)

O ***IKOS*** identificou corretamente o programa como potencialmente inseguro por quatro razões. As duas primeiras razões referem-se à possível utilização do valor de `argv[1]` sem ter sido inicializado, podendo, por isso, ser nulo. No entanto, estes dois casos não se aplicam na prática, porque, ao verificar-se que `argc > 1`, garante-se que `argv[1]` contém algum valor, nomeadamente o *input* fornecido pelo utilizador ao programa. Após isso, surge mais um aviso relativamente ao conteúdo de `argv[1]` enquanto acesso a memória, mas também não é esse o objeto principal da análise de vulnerabilidades. Finalmente, o último aviso da ferramenta salienta a possibilidade da ocorrência de um *buffer overflow*, como é o caso. O ***IKOS*** conseguiu identificar esta vulnerabilidade devido ao seu modo de funcionamento: contém uma lista de funções potencialmente inseguras e emite um alerta se alguma dessas funções for utilizada - como é o caso de `strcpy()` -, juntamente com sugestões para evitar essa vulnerabilidade.

A ferramenta ***Frama-C*** não foi testada, por ser especialmente focada em programas de tamanho industrial escritos em ISO C99, o que não se aplica nesta situação em particular, dada a simplicidade do código. Por já terem sido experimentadas outras ferramentas estáticas, descartou-se a utilização de ***SMACK***. Além disto, não sendo este um caso para o qual faz sentido realizar *constant-time analysis*, não se correu ***ctverif***.

Por último, foi executada a ferramenta ***infer*** para experimentar mais uma análise estática para erros de memória, de forma semelhante a ***scan-build***.

![infer](/Lab1/images/145-infer.png)

Esta análise - executada quer com as verificações predefinidas do ***infer***, quer com a *flag* `--bufferoverrun` - não detetou quaisquer erros, como é visível através do seu *output*.

### Conclusão

Relativamente às ferramentas dinâmicas, tanto o ***Valgrind*** quanto o ***Address Sanitizer*** identificaram corretamente o problema. Privilegia-se, no entanto, o ***Address Sanitizer*** devido à informação extra que providencia, como o endereço de memória onde ocorre o *stack buffer overflow*. Tanto o ***IKOS*** como o ***scan-build*** sinalizaram o comando `strcpy()` como potencialmente perigoso, mas não ofereceram mais informação por não terem contexto adicional. O ***infer*** não identificou nenhum problema. Conclui-se, então, que a análise dinâmica aparenta ser mais útil para este tipo de problemas, visto que a análise estática é pouco informativa/explícita sobre a existência efetiva da vulnerabilidade em questão.

Em síntese, as ferramentas dinâmicas auxiliaram a encontrar a vulnerabilidade ao, perante certos *inputs*, sinalizarem corretamente a ocorrência de um *buffer overflow*. As ferramentas estáticas salientaram a possível falha de segurança na utilização da função `strcpy()` o que, ainda que não explicite exatamente a vulnerabilidade em questão, contribui para o desenvolvimento de código mais seguro.

As principais limitações encontradas residiram na baixa relevância das mensagens de erro das ferramentas estáticas, bem como na necessidade de correr o programa com *inputs* específicos para que as ferramentas dinâmicas emitissem o alerta adequado para o erro, visto que *inputs* pequenos não originam qualquer *stack overflow*, mas a vulnerabilidade não deixa de existir nem de ser explorável. Além disso, foi necessário utilizar as *flags* corretas do ***Address Sanitizer*** (`fsanitize=address` e `fsanitize=undefined`) para ativar os *sanitizers* apropriados à deteção desta vulnerabilidade. Em nenhum caso foi necessário alterar o código original do programa, o que é um aspeto positivo a realçar.

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

Este código apresenta uma vulnerabilidade de *command injection*, visto que o *input* do utilizador obtido do *standard input* (`stdin`) para o *array* `buff` é concatenado pela função `strcat()` no *array* `sys`, que contém previamente o valor da variável `cmd` - ou seja, o comando `/usr/bin/cat` - que será executado pelo sistema através da chamada à função `system()`. Como tal, um atacante pode inserir um *input* malicioso que, após a execução do comando `/usr/bin/cat ...`, execute outro comando arbitrário, realizando um ataque de *command injection*.

Efetivamente, as execuções seguintes demonstram a execução de diferentes comandos fornecidos como *input* ao programa, contornando o seu propósito de executar unicamente `cat` e concretizando, assim, um ataque de *command injection*.

![Exemplos de Execução](/Lab1/images/155-example.png)

Assim sendo, existe uma principal CWE associada a esta vulnerabilidade:

1. **[CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')](https://cwe.mitre.org/data/definitions/78):** o programa constrói parte de um comando do sistema operativo utilizando *input* externo fornecido pelo utilizador, mas sem neutralizar os elementos que podem modificar o comportamento esperado do comando a executar, tal como demonstra a imagem abaixo.

![CWE 78](/Lab1/images/155-cwe.png)

Note-se que, dadas as chamadas às funções `strcpy()` e `strcat()` sem a devida validação do tamanho do *input*, podem ainda ser concretizados ataques de *buffer overflow*, tal como explicado anteriormente. Como estes casos estão igualmente associados às CWEs anteriores, não serão novamente explorados.

O programa contido em `os_cmd_scope-good.c` apresenta uma possível correção para esta falha.

```c
#define SIZE_CMD 10
const char cmd[SIZE_CMD] = "/bin/cat ";

/*
	One of the most basic filtering, remove the ';'

	SAMATE Edit: replaced by whitelisting to prevent command injection based on other operators like "&&"
*/
void purify(char *__buff)
{
	char buf[BUFSIZ]="";
	char *c = __buff, *b = buf;
	for (;*c != '\0';c++)
	{
			if(isalnum(*c) || *c == '/' || *c == '_' || *c == ' ' || *c == '.')
				*b++ = *c;
	}
	*b = '\0';
	strcpy(__buff, buf);
}

void runCommand(char *str) 
{
	purify(str);    						            /* FIX */
	if (system(str) < 0)
		fprintf(stderr, "Error running command %s\n", str);
}

int main(int argc, char *argv[])
{
	char sys[BUFSIZ]="";
	char buff[BUFSIZ];
	if (fgets(buff,BUFSIZ - SIZE_CMD,stdin))
	{
		strcat(sys, cmd);
		strcat(sys, buff);
		runCommand(sys);
	}
	return 0;
}
```

No código exposto, a função `purify()` é chamada antes da execução do comando pelo sistema operativo. Ora, esta função é responsável por realizar *whitelisting* do *input* introduzido pelo utilizador de maneira a prevenir a injeção de comandos, removendo todos os caracteres que não sejam alfanuméricos, `/`, `_`, ` ` ou `.`, ou seja, impedindo a execução de múltiplos comandos através dos operadores `;`, `|` ou `&&`, por exemplo. Deste modo, corrige-se a vulnerabilidade de *command injection* anteriormente existente.

### *Vulnerability Scanners*

Como o código do programa está também escrito em C/C++, pode correr-se o *scanner* de vulnerabilidades ***Flawfinder***.

![Flawfinder](/Lab1/images/155-flawfinder.png)

De facto, o ***Flawfinder*** deteta corretamente a vulnerabilidade de *command injection* em causa no código exposto, identificando a CWE associada (CWE-78), tal como seria expectável. A par disso, esta ferramenta alerta ainda para as restantes CWEs já abordadas (CWE-119 e CWE-120), relacionadas com os possíveis ataques de *buffer overflow*.

De forma análoga à anterior, testou-se também o ***Snyk Code Checker*** para este caso.

![Snyk Code Checker](/Lab1/images/155-snyk.png)

Ora, o ***Snyk Code Checker*** também identifica corretamente a falha no código e a CWE associada. Esta conclusão é alcançada através da realização de *taint analysis*, tal como é possível verificar pelos termos *source* e *sink* apresentados na interface.

Finalmente, foi igualmente executado o ***SemGrep***.

![SemGrep](/Lab1/images/155-semgrep-1.png)

![SemGrep](/Lab1/images/155-semgrep-2.png)

Para além de realçar a vulnerabilidade de *command injection* devido à ausência de neutralização do *input*, o ***SemGrep*** alerta para a chamada à função `system()`, que deve ser evitada precisamente por permitir a execução de múltiplos comandos de forma eventualmente indevida. Assim sendo, a ferramenta sugere a utilização de outras interfaces mais restritivas, como `execve()`. Em ambas as situações, a CWE-78 é corretamente identificada.

Em conclusão, todos os *vulnerability scanners* experimentados foram capazes de assinalar a vulnerabilidade presente. Isto dever-se-á ao facto de as três ferramentas realizarem *taint analysis* para identificarem o fluxo percorrido pelo *input* do utilizador, de maneira a observarem que este acaba por ser incluído na chamada à função `system()`, para ser posteriormente executado. Efetivamente, as ferramentas assinalaram o facto de ser introduzido *input* não sanitizado em chamadas ao sistema operativo, o que constituiu uma vulnerabilidade passível de ser explorada. Esta conclusão materializa-se no mapeamento correto nas CWEs associadas, automaticamente.

### Ferramentas de Análise

No sentido de analisar esta vulnerabilidade de *command injection*, foram selecionadas várias ferramentas dinâmicas e estáticas.

#### Análise Dinâmica

A ferramenta ***Valgrind*** não é adequada para este caso, visto que o seu propósito é analisar erros de memória e não vulnerabilidades de *command injection*. Este facto é facilmente comprovável através da execução da mesma, que não retorna qualquer *output* relevante.

![Valgrind](/Lab1/images/155-valgrind-1.png)

![Valgrind](/Lab1/images/155-valgrind-2.png)

Igualmente, também o ***Address Sanitizer*** é apropriado para detetar erros de memória e não falhas de segurança de *command injection*, pelo que a sua execução é dispensável, tal como se verifica pelos exemplos abaixo.

![Address Sanitizer fsanitize=address](/Lab1/images/155-addresssanitizer-address.png)

![Address Sanitizer fsanitize=leak](/Lab1/images/155-addresssanitizer-leak.png)

![Address Sanitizer fsanitize=memory](/Lab1/images/155-addresssanitizer-memory.png)

![Address Sanitizer fsanitize=undefined](/Lab1/images/155-addresssanitizer-undefined.png)

De facto, uma das ferramentas dinâmicas mais relevantes para analisar problemas deste tipo é o ***Taintgrind***. Assim, através de ligeiras alterações no código, é possível "pintar" o *input* do utilizador (*source*) para verificar se ele alcança, ou seja, "pinta", o *input* fornecido à chamada à função `system()` (*sink*). Abaixo mostram-se as modificações efetuadas no código, destacando-se as linhas acrescentadas ao ficheiro, bem como a respetiva execução com o ***Taintgrind***.

```c
#include <valgrind/taintgrind.h>

#define SIZE_CMD 14
const char cmd[SIZE_CMD] = "/usr/bin/cat ";

void runCommand(char *str) 
{
	/* TAINTGRIND */
	unsigned int t;
	for (int i = 0; i < strlen(str); ) {
		TNT_IS_TAINTED(t, str + i, 8);
		printf("%08x ", t);
		i += 8;
	}

	if(system(str) < 0)							        /* FLAW */
		fprintf(stderr, "system() failed");
}

int main(int argc, char *argv[])
{
	char sys[512];
	char buff[512];
	if (fgets(buff,512 - SIZE_CMD,stdin))
	{
		TNT_TAINT(buff, 8);								/* TAINTGRIND */
		strcpy(sys, cmd);
		strcat(sys, buff);
		runCommand(sys);
	}
	return 0;
}
```

![Taintgrind](/Lab1/images/155-taintgrind.png)

Tal como é possível verificar no *output* do ***Taintgrind*** (`00000000 00000000 ffffffff 00000000`), parte do comando fornecido à chamada à função `system()` está "pintado" (`ffffffff`), ou seja, corresponde ao *input* introduzido pelo utilizador. Deste modo, comprova-se a existência da vulnerabilidade de *command injection* previamente explicada, visto que o *input* do utilizador é utilizado para a execução direta de um comando no sistema operativo.

De forma semelhante, a ferramenta ***Clang Data Flow Sanitizer*** foi utilizada para observar o fluxo do *input* do utilizador durante a execução do programa. Assim como anteriormente, foram feitas pequenas modificações no código original para "pintar" o *input* do utilizador e verificar se o comando a executar pelo sistema também está "pintado". De seguida, expõem-se as alterações no código e a execução correspondente.

```c
#include <sanitizer/dfsan_interface.h>

#define SIZE_CMD 14
const char cmd[SIZE_CMD] = "/usr/bin/cat ";

void runCommand(char *str) 
{
	/* CLANG DATA FLOW SANITIZER */
	dfsan_label command_label;
	for (int i = 0; i < strlen(str); ) {
		command_label = dfsan_read_label(str + i, 8);
		printf("%u ", command_label);
		i += 8;
	}

	if(system(str) < 0)							        /* FLAW */
		fprintf(stderr, "system() failed");
}

int main(int argc, char *argv[])
{
	char sys[512];
	char buff[512];
	if (fgets(buff,512 - SIZE_CMD,stdin))
	{
		/* CLANG DATA FLOW SANITIZER */
		dfsan_label buff_label = 1;
		dfsan_set_label(buff_label, buff, 8);
		strcpy(sys, cmd);
		strcat(sys, buff);
		runCommand(sys);
	}
	return 0;
}
```

![Clang Data Flow Sanitizer](/Lab1/images/155-dfsan.png)

Efetivamente, confirma-se, através do resultado da execução (`0 1 1 0`), que o comando executado pela função `system()` está parcialmente "pintado", pelo que se conclui que provém diretamente do *input* fornecido pelo utilizador. Como tal, evidencia-se a vulnerabilidade de *command injection*, dado que o utilizador é capaz de injetar um comando para execução de forma indevida.

O ***TIMECOP*** não foi executado contra este exemplo, visto que não é pertinente explorar *constant-time analysis* para a deteção da vulnerabilidade em causa, por não se tratar de um *timing attack*.

#### Análise Estática

No que concerne à análise estática deste programa, testaram-se as ferramentas mais apropriadas.

Em primeiro lugar, executou-se o ***scan-build*** tendo em vista a deteção de erros de programação no código C/C++.

![scan-build](/Lab1/images/155-scanbuild.png)

Ora, o resultado da execução mostra que o ***scan-build*** não foi capaz de detetar a falha de *command injection* presente no programa, dado que apenas alertou para a utilização das funções `fprintf()`, `strcpy()` e `strcat()`, que são consideradas inseguras por não terem as verificações de segurança necessárias. No entanto, não foi assinalada qualquer possibilidade de *command injection*.

Em segundo lugar, foi corrida a ferramenta ***IKOS*** para realizar uma análise semelhante.

![IKOS](/Lab1/images/155-ikos-1.png)

![IKOS](/Lab1/images/155-ikos-2.png)

Similarmente, o ***IKOS*** também não detetou a vulnerabilidade de *command injection*, limitando-se a assinalar que a chamada à função `system()` pode representar uma falha de segurança. Contudo, este aviso surge sempre que exista qualquer chamada a `system()` no código do programa analisado, independentemente de serem - ou não - efetuadas as verificações de segurança adequadas. Além disso, foram ainda lançados 6 avisos relativos a erros de memória potencialmente não inicializada ou indevidamente acedida, mas não são o principal objeto da análise a efetuar.

Em terceiro lugar, experimentou-se a utilização de ***Frama-C*** para detetar *command injection*. Para tal, modificou-se ligeiramente o código original e lançou-se a GUI do ***Frama-C***, o que se expõe abaixo.

```c
#include "__fc_builtin.h"

#define SIZE_CMD 14
const char cmd[SIZE_CMD] = "/usr/bin/cat ";

void runCommand(char *str) 
{
	//@ admit str[strlen(str) - 1] == '\0';
	//@ assert !\tainted(str[0..strlen(str) - 1]);
	if(system(str) < 0)							        /* FLAW */
		fprintf(stderr, "system() failed");
}

int main(int argc, char *argv[])
{
	char sys[512];
	char buff[512];
	if (fgets(buff,512 - SIZE_CMD,stdin))
	{
		char* buf = buff;
		//@ taint buf[0..strlen(buf)];
		strcpy(sys, cmd);
		strcat(sys, buff);
		runCommand(sys);
	}
	return 0;
}
```

![Frama-C](/Lab1/images/155-framac.png)

Ora, o resultado apresentado pelo ***Frama-C*** não foi conclusivo, visto que a asserção foi considerada com estado desconhecido. Dada a diversidade de ferramentas já utilizadas, não se realizou uma exploração mais profunda deste problema.

Já tendo sido feita uma análise abrangente do problema em causa, optou-se por não se executar a ferramenta ***SMACK***. A par disso, também não se usou ***ctverif***, por não fazer sentido realizar *constant-time analysis* neste programa.

Por último, foi corrida a ferramenta ***infer***, para experimentar mais uma abordagem de *taint analysis*. Para tal, foi acrescentada a linha `taint(buff)` ao ficheiro com o código original, de modo a "pintar" o *input* do utilizador, resultando no código abaixo.

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
		taint(buff);									/* INFER */
		strcpy(sys, cmd);
		strcat(sys, buff);
		runCommand(sys);
	}
	return 0;
}
```

Além disso, foi criado o ficheiro `.inferconfig`, com o seguinte conteúdo.

```
{
  "force-delete-results-dir": true,
  "quandary-sources": [
    {
      "procedure": "taint",
      "kind": "Other",
      "index": "0"
    }
  ],
  "quandary-sinks": [
  ],
  "quandary-sanitizers": [
  ],
  "quandary-endpoints": [
  ]
}
```

Assim, foi executada a ferramenta ***infer***, obtendo-se o *output* exposto.

![infer](/Lab1/images/155-infer.png)

Ao contrário do esperado, o resultado não mostra que, no *sink*, o conteúdo esteja "pintado". Apesar de o ***infer*** definir automaticamente algumas funções críticas - como é o caso de `system()` - como *sinks* e de o conteúdo de `buff` estar corretamente "pintado" - dada a chamada à função `taint(buff)` -, a ferramenta não encontrou qualquer problema com o código, deixando escapar a vulnerabilidade de *command injection*. Outras tentativas de obter um resultado diferente envolveram alterar o arquivo `.inferconfig` para que, ao ajustar as definições das `quadrary-sources` e/ou das `quadrary-sinks`, a ferramenta pudesse reconhecer com precisão a vulnerabilidade. No entanto, estas alterações não foram bem-sucedidas, continuando a vulnerabilidade por detetar.

### Conclusão

Concluindo, as ferramentas dinâmicas capazes de realizar *taint analysis* (***Taintgrind*** e ***Clang Data Flow Sanitizer***) conseguiram detetar corretamente a falha de *command injection*. Além disso, tal como seria expectável, as ferramentas para análise de memória (***Valgrind*** e ***Address Sanitizer***) não identificaram qualquer problema com o programa. Por seu lado, as técnicas de análise estática (***scan-build***, ***IKOS***, ***Frama-C*** e ***infer***) também não alertaram para a falha de *command injection*.
Assim sendo, não há dúvidas de que a análise dinâmica é a mais adequada para detetar vulnerabilidades deste tipo.

Em resumo, as abordagens dinâmicas, através de *taint analysis*, evidenciaram que o *input* proveniente do utilizador e não sanitizado alcançava a chamada à função `system()`, constituindo uma falha de segurança. As técnicas de análise estática não foram capazes de assinalar este problema, demonstrando-se ineficazes neste caso.

Assim, surgem limitações evidentes na utilização de ferramentas estáticas para a deteção de *command injection*, visto que não foi possível identificar o problema em questão, facilmente visível pelas ferramentas dinâmicas. A par disso, note-se que, para as análises dinâmicas serem bem-sucedidas, foi necessário, em todos os casos, efetuar algumas modificações no código original - de modo a identificar a *source* e o *sink* -, o que aumenta o trabalho manual exigido para o desenvolvimento de *software* seguro. Ainda assim, feitas as alterações necessárias, as técnicas dinâmicas funcionaram conforme esperado, identificando o problema tal como pretendido.

## Análise Global

Em suma, apresentam-se abaixo os resultados obtidos por todas as ferramentas utilizadas para as vulnerabilidades em causa: *buffer overflow* e *command injection*.

| ***Vulnerability Scanners*** | *Buffer Overflow* | *Command Injection* |
| ---------------------------- | ----------------- | ------------------- |
| ***Flawfinder***             |        SIM        |         SIM         |
| ***Coverity***               |         -         |          -          |
| ***GitHub Code Scanning***   |         -         |          -          |
| ***GitLab***                 |         -         |          -          |
| ***SonarCloud***             |         -         |          -          |
| ***Snyk Code Checker***      |        SIM        |         SIM         |
| ***SemGrep***                |        NÃO        |         SIM         |

| Ferramentas de Análise Dinâmica | *Buffer Overflow* | *Command Injection* |
| ------------------------------- | ----------------- | ------------------- |
| ***Valgrind***                  |        SIM        |         NÃO         |
| ***Address Sanitizer***         |        SIM        |         NÃO         |
| ***Taintgrind***                |         -         |         SIM         |
| ***Clang Data Flow Sanitizer*** |         -         |         SIM         |
| ***TIMECOP***                   |         -         |          -          |

| Ferramentas de Análise Estática | *Buffer Overflow* | *Command Injection* |
| ------------------------------- | ----------------- | ------------------- |
| ***scan-build***                |        SIM        |         NÃO         |
| ***IKOS***                      |        SIM        |         NÃO         |
| ***Frama-C***                   |         -         |         NÃO         |
| ***SMACK***                     |         -         |          -          |
| ***ctverif***                   |         -         |          -          |
| ***infer***                     |        NÃO        |         NÃO         |

Globalmente, conclui-se que, por um lado, tanto as ferramentas de análise dinâmica quanto as ferramentas de análise estática são boas para detetar casos de *buffer overflow*. Por outro lado, apenas as ferramentas de análise dinâmica são capazes de, através de *taint analysis*, identificar a falha de *command injection*.
