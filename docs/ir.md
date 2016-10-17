# 中间语言

由于angr需要处理很多不同的架构，所以它必须选择一种中间语言（IR）来进行它的分析。我们使用Valgrind的中间语言，VEX来完成这方面的内容。VEX中间语言抽象了几种不同架构间的区别，允许在他们之上进行统一的分析：

- **寄存器名**。在不同架构间的寄存器数量和名字是不一样的，但是现代的各CPU设计有通用之处：每一种CPU包含几个通用寄存器，一个寄存器装载栈指针，一系列寄存器装载状态标志等等。中间语言提供了一个统一的、抽象的对于不同平台的寄存器接口。VEX模型将寄存器作为一个独立的内存空间，使用偏移来访问它们（比如，AMD64的rax寄存器在这个内存空间的偏移16的地址上）。
- **内存访问**。不同的架构使用不同的方式访问内存。比如ARM既可以通过小端序也可以通过大端序来访问内存。中间语言必须能够抽象分离出其中的差异。
- **内存分段**。一些架构，比如x86，通过使用特殊的段寄存器实现内存的分段。中间语言能够理解这样 的内存访问机制。
- **指令的副作用**。大多数的指令有产生一些影响。比如，ARM中Thumb模式下的大多数操作会更新状态标志，栈上的push/pop操作更新栈指针。在分析中通过*ad hoc* 的方式来跟踪这些影响是愚蠢的，所以中间语言使这些影响很清晰直接。

对我们来说中间语言有很多选择，我们选择了VEX，因为将二进制代码转换为VEX已经有了很好的支持。VEX是一种支持大量目标机器语言的架构无关、无副作用的语言。它抽象了机器指令到中间表达来使程序更易于分析。这一中间语言有四个主要的对象类：

- **表达式（Expressions）**。IR表达式代表了一个计算出的数值或者常量。这包括了内存装载，读寄存器以及算数计算的结果。
- **操作（Operations）**。IR操作描述了对IR表达式的修改。这包括了整形的运算，浮点型的运算，位运算等等。一个IR操作应用于IR表达式会产生一个IR表达式作为结果。
- **临时变量（Temporary variables）**。VEX使用临时变量作为内部寄存器：IR表达式在使用过程中存储在临时变量中。临时变量的值可以通过IR表达式重新获取。这些临时变量被从t0开始编号，且是强类型的（比如64位的整形或者32位的浮点型）。
- **语句（Statements）**。IR语句模型根据目标机器而改变，比如内存存储和写寄存器产生的效果，IR语句使用IR表达式获取可能用到的值。比如，一个内存存储操作的IR语句使用IR表达式作为要写入的目标地址，使用另一个IR表达式作为要写入的内容。
- **块（Blocks）**。一个IR块是一系列IR语句的集合，代表了目标架构上的一个扩展块（术语为“IR超级块（IR Super Block）”或者“IRSB”）。一个超级块可以有多个出口。在基本块中间有条件退出时，会使用特殊的*退出*IR语句。一个IR表达式被用来代表在块的最后无条件退出时的目标指向。

在VEX仓库中，VEX IR在`libvex_ir.h`文件中有很好的文档说明（https://github.com/angr/vex/blob/master/pub/libvex_ir.h）。我们在这里详细列出部分你可能会频繁使用的一个IR表达式：

| IR 表达式          | 评估值                                      | VEX 输出示例            |
| --------------- | ---------------------------------------- | ------------------- |
| Constant        | 一个常量值                                    | 0x4:I32             |
| Read Temp       | 存储在VEX临时变量中的值。                           | RdTmp(t10)          |
| Get Register    | 存储在一个寄存器中的值。                             | GET:I32(16)         |
| Load Memory     | 存储在内存中的值，通过另一个IR表达式来指定地址。                | LDle:I32 / LDbe:I64 |
| Operation       | IR操作的结果，作为指定的IR表达式的参数。                   | Add32               |
| If-Then-Else    | 如果给定的IR表达式值为0，返回一个IR表达式，否则返回另一个。         | ITE                 |
| Helper Function | VEX使用C的帮助函数执行确定的操作，比如计算确定架构上的状态标志寄存器。这些函数返回IR表达式。 | function\_name()    |

这些表达式使用于IR语句中。这些是一些常见的IR语句：

| IR 语句        | 含义                                     | VEX 输出示例                                 |
| ------------ | -------------------------------------- | ---------------------------------------- |
| Write Temp   | 使用给定的IR表达式设置一个VEX临时变量。                 | WrTmp(t1) = (IR Expression)              |
| Put Register | 使用给定的IR表达式更新寄存器。                       | PUT(16) = (IR Expression)                |
| Store Memory | 使用给定的IR表达式作为地址，另一个IR表达式作为值，更新目标内存。     | STle(0x1000) = (IR Expression)           |
| Exit         | 从基本块中的条件退出，使用IR表达式指定跳转目标。其条件也由IR表达式指定。 | if (condition) goto (Boring) 0x4000A00:I32 |

下面是将ARM架构上的指令转换成VEX IR的一个例子。在这个例子中，减操作被转换成一个由5个IR语句组成的IR块，每一个语句包含至少一个IR表达式（虽然在实际应用中，一个IR块基本都不止一条指令）。寄存器名被转换成大量的索引传递给GET表达式和PUT表达式。精明的读者将会注意到实际的减法操作由前4个IR语句完成，将程序指针指向下一个指令（在这个例子中应该是`0x59FC8`）由最后一条指令完成。

下面是ARM指令：

```
subs R2, R2, #8
```

转换为VEX IR：

```
t0 = GET:I32(16)
t1 = 0x8:I32
t3 = Sub32(t0,t1)
PUT(16) = t3
PUT(68) = 0x59FC8:I32
```

既然你已经懂得了VEX，你可以动手试一试angr中的VEX：我们使用一个叫做PyVEX的库（https://github.com/angr/pyvex）作为VEX和python的接口。PyVEX实现了它自己的友好输出，所以它可以显示寄存器名而不是使用在PUT和GET操作中的寄存器偏移。

PyVEX可以通过 `Project.factory.block`接口来访问。有很多种不同的对象可以用来来访问一个块的属性，但是他们在分析特定的字节序列的时候具有共通特性。通过`factory.block` 构造器，你可以得到一个能够轻松转换成几种不同代表的 `Block`对象。尝试`.vex` 来获取PyVEX的IRSB，或者`.capstone`获取Capstone块。

让我们来使用PyVEX：

```python
>>> import angr

# 装载二进制程序
>>> b = angr.Project("/bin/true")

# 转换入口点为基本块
>>> irsb = b.factory.block(b.entry).vex
>>> irsb.pp()

# 转换特定地址为基本块
>>> irsb = b.factory.block(0x401340).vex
>>> irsb.pp()

# 这是代表了这一基本块的最后无条件退出时的跳转目标的IR表达式
>>> print irsb.next

# 这一无条件退出的类型（比如，一个函数调用，或者从一个函数返回，或者是系统调用等等）
>>> print irsb.jumpkind

# 你也可以将它以良好的可读方式打印出来
>>> irsb.next.pp()

# 遍历每一个语句并且将它们打印出来
>>> for stmt in irsb.statements:
...     stmt.pp()

# 打印代表了数据的IR表达式以及其被对应的存储语句存储下来的类型
>>> import pyvex
>>> for stmt in irsb.statements:
...     if isinstance(stmt, pyvex.IRStmt.Store):
...         print "Data:",
...         stmt.data.pp()
...         print ""
...         print "Type:",
...         print stmt.data.result_type
...         print ""

# 打印基本块中每一个条件退出的条件和跳转目标
... for stmt in irsb.statements:
...     if isinstance(stmt, pyvex.IRStmt.Exit):
...         print "Condition:",
...         stmt.guard.pp()
...         print ""
...         print "Target:",
...         stmt.dst.pp()
...         print ""

# 这些是在IRSB中的每一个临时变量的类型
>>> print irsb.tyenv.types

# 这是获取第0个临时变量的类型的一种方法
>>> print irsb.tyenv.types[0]
```

记住这是一个基本块的句法表达。也就是说，它会告诉你这个块表示什么，但是你没有任何上下文可以联系，比如说一个存储指令究竟存储了什么数据。我们会在以后进一步理解这一点。