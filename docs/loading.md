# 装载二进制文件 - CLE和angr Project

angr的二进制装载组件是CLE，它负责装载二进制对象（以及它依赖的任何库）和把这个对象以易于操作的方式交给angr的其他组件。

CLE的主要目标是使用强大的方式来装载二进制文件，类似于真实的装载器（比如GNU LD装载ELF文件那样）来装载它们。这意味着二进制文件中的部分信息将会被CLE忽略，因为这些信息可能是被删减过的或是有意无意地破坏过的，这在嵌入式世界中很常见。

angr将这些包含在*Project*类中。一个Project类是代表了你的二进制文件的实体。你与angr的大部分操作都会经过它。

使用angr装载一个二进制文件（比如说，“/bin/true”），你需要这样做：

```python
>>> import angr

>>> b = angr.Project("/bin/true")
```

这样操作之后，b就是你的主二进制文件以及它依赖的所有库的代表。这时，即便你没有进一步关于angr的知识，你也可以做一些基础的事情比如：

```python
# 这是二进制文件的入口点
>>> print b.entry

# 这些是二进制文件内存空间中的最小地址和最大地址
>>> print b.loader.min_addr(), b.loader.max_addr()

# 这些是文件的全名
>>> print b.filename
```

CLE通过这个装载类来呈现二进制文件的信息。CLE装载器（cle.Loader）代表了已经装载了的和映射到内存空间中的CLE二进制对象。每一种二进制对象都由一种可以处理这种文件类型的后端装载器（cle.Backend的子类）装载。比如cle.ELF用来装载ELF文件。

CLE可以像下面这样来交互：

```python
# 这是一个CLE装载器对象
>>> print b.loader

# 这是一个dict，包含着已经作为二进制文件的一部分而装载的对象（它们的种类取决于后端装载器）
>>> print b.loader.shared_objects

# 这是装载后的进程的内存空间。它包含具体地址与该地址上的值
>>> print b.loader.memory[b.loader.min_addr()]

# 这是主要的二进制对象（种类取决于后端装载器）
>>> print b.loader.main_bin

# 它们取回映射在指定地址的二进制对象
>>> print b.loader.addr_belongs_to_object(b.loader.max_addr())

# 获取指定符号的GOT条目（在主二进制对象中）
>>> print b.loader.find_symbol_got_entry('__libc_start_main')
```

你也可以直接与独立的二进制对象交互：

```python
# 这是程序依赖的库名的list
# 通过读取Elf文件的dynamic section的DT_NEEDED域获取
>>> print b.loader.main_bin.deps

# 这是关于主二进制对象的内存内容的dict
>>> print b.loader.main_bin.memory

# 这是一个装载的libc所需的导入条目的dict（name->ELFRelocation）
>>> b.loader.shared_objects['libc.so.6'].imports

# 这是一个主二进制对象所需的导入条目的dict（name->ELFRelocation），其地址通常是0（请看下面的“杂项”一节）
>>> print b.loader.main_bin.imports
```

## 装载依赖项

CLE将会默认地尝试装载主二进制文件所需的所有依赖（比如libc.so.6，ld-linux.so.2等），除非装载选项中的`auto_load_libs`设置为`False`。当装载库文件的时候，如果无法找到，装载器会默认忽略产生的错误并标记所有关于那个库的依赖是为解决的。你也可以改变装载器的这一行为。

## 装载选项

装载选项可以传递给Project（它会传递给CLE）。

CLE需要一个参数的dict。需要应用到库而不是目标主二进制的需要通过lib_opts参数来传递：

```python
load_options = {'main_opts':{options0}, 'lib_opts': {libname1:{options1}, path2:{options2}, ...}}

# 或者以更易读的方式
load_options = {}
load_options['main_opts'] = {k1:v1, k2:v2 ...}
load_options['lib_opts'] = {}
load_options['lib_opts'][path1] = {k1:v1, k2:v2, ...}
load_options['lib_opts'][path2] = {k1:v1, k2:v2, ...}
etc.
```



### 有效的选项

```python
>>> load_options = {}

# 是否需要装载动态链接库
>>> load_options['auto_load_libs'] = False

# 无论是否是目标二进制文件所需要的，强制装载的库的list
>>> load_options['force_load_libs'] = ['libleet.so']

# 需要跳过的库的list
>>> load_options['skip_libs'] = ['libc.so.6']

# 装载主二进制文件时的选项
>>> load_options['main_opts'] = {'backend': 'elf'}

# 映射库名到其装载时需要使用的选项dict的dict
>>> load_options['lib_opts'] = {'libc.so.6': {'custom_base_addr': 0x13370000}}

# 可以进行额外搜索的路径list
>>> load_options['custom_ld_path'] = ['/my/fav/libs']

# 是否将文件名中版本号不同的库视作相同的，比如libc.so.6和libc.so.0
>>> load_options['ignore_import_version_numbers'] = False

# 在重定位共享对象的基址的时候需要使用的对齐值
>>> load_options['rebase_granularity'] = 0x1000

# 如果找不到一个库，抛出一个异常（默认行为是忽略未找到的库）
>>> load_options['except_missing_libs'] = True
```

接下来的选项被应用于每一个对象并且覆盖CLE的自动检测。

它们可以通过main_opts或者lib_opts来应用。

```python
# 装载二进制文件的基址
>>> load_options['main_opts'] = {'custom_base_addr':0x4000}

# 指定对象的后端装载器（下面有相关的讨论）
>>> load_options['main_opts'] = {'backend': 'elf'}
```

对同一二进制文件使用多选项的例子：

```python
>>> load_options['main_opts'] = {'backend':'elf', 'custom_base_addr': 0x10000}
```

## 后端

CLE现在有对于ELF、PE、CGC和ELF核心转储文件的后端支持，像IDA装载二进制文件一样将文件装载到平坦的地址空间中。在大部分时间中，CLE会自动检测需要使用的正确后端，所以你不需要指定后端类型除非你在处理一些奇怪的东西。

你可以通过在选项中包含一个关键字的方式来指定后端。如果你需要强制指定目标文件的架构而不是自动检测，你可以通过custom_arch关键字。这个关键字不需要完全匹配上具体的架构列表，angr能够通过其所支持的架构的几乎所有常见的标识符来识别出你给出的架构。

```python
>>> load_options = {}
>>> load_options['main_opts'] = {'backend': 'elf', 'custom_arch': 'i386'}
>>> load_options['lib_opts'] = {'libc.so.6': {'backend': 'elf'}}
```

| 后端关键字     | 描述                          | 需要 `custom_arch`? |
| --------- | --------------------------- | ----------------- |
| elf       | 基于PyELFTools的ELF装载器         | no                |
| pe        | 基于PEFile的PE装载器              | no                |
| cgc       | Cyber Grand Challenge文件的装载器 | no                |
| backedcgc | 支持指定内存和寄存器支持的CGC文件装载器       | no                |
| elfcore   | ELF核心转储文件的装载器               | no                |
| ida       | 启动IDA来解析文件                  | yes               |
| blob      | 装载文件到内存中作为一个平坦的镜像           | yes               |

既然你已经装载了一个二进制文件，你已经可以通过`b.loader.main_bin`来获取一些有意思的信息。比如，共享库依赖，导入的库、内存、符号以及其他的list。充分使用IPython的tab补全来查看有趣的函数和选项吧。

现在是时候看看[IR支持](./ir.md)了。

## 杂项

### 导入项

接下来的是和ELF相关的。

在大多数架构上，导入项，比如一些符号引用自二进制文件之外（共享库）中的函数或者全局变量会出现在符号表中，它们的地址往往都是0。在一些架构比如MIPS中，它包含了函数的PLT内容的地址（在代码段中）。

如果你在寻找某一符号的GOT条目（在数据段中），可以看看jmprel。它是一个dict（符号->GOT地址）。

无论你是在找PLT条目还是GOT条目，都依赖于架构。架构相关的内容定义在Archinfo仓库的一个类中。我们对不同架构下函数的绝对地址的处理定义在这个类的got_section_name属性中。

有关ELF装载和架构相关的进一步细节，你可以参阅[可执行文件和可链接文件格式文档](http://www.cs.northwestern.edu/~pdinda/icsclass/doc/elf.pdf)以及每一个架构（[MIPS](http://math-atlas.sourceforge.net/devel/assembly/mipsabi32.pdf), [PPC64](http://math-atlas.sourceforge.net/devel/assembly/PPC-elf64abi-1.7.pdf), [AMD64](http://www.x86-64.org/documentation/abi.pdf)）的ABI实现。

```python
>>> rel = b.loader.main_bin.jmprel
```

### 符号分析

Project默认尝试替换对库函数的外部调用，通过使用在[符号总结](./todo.md)中标明的SimProcedures（是关于函数如何影响state的总结）。

当指定函数没有相关总结的时候：

- 如果`auto_load_libs`是`True`（默认值），真正的库函数会被执行。这可能正是也可能不是你想要的，取决于具体的函数。比如说一些libc的函数分析起来过于复杂并且很有可能引起[path](./paths.md)对其的尝试执行过程中的state数量的爆炸增长。
- 如果`auto_load_libs`是`False`，且外部函数是无法找到的，并且Project会将它们引用到一个通用的叫做`ReturnUnconstrained`的`SimProcedure`上去，它就像它的名字所说的那样：它返回一个不受约束的值。
- 如果`use_sim_procedures`（这是一个传递给angr.Project的参数，不是给cle.Loader的）是`False`的话（默认是True），那么除了`ReturnUnconstrained`意外没有`SimProcedure`会被使用。
- 你可以指定一些符号不被`SimProcedures`替换，这通过传递给`angr.Project`的`exclude_sim_procedures_list`和`exclude_sim_procedures_func`来完成。
- 通过参阅`angr.Project._use_sim_procedures`的源码来查看具体的算法。

