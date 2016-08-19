顶层接口
====================

当你已经装载了一个工程，下面该做什么呢？

这篇文档解释了可以直接从`angr.Project`中得到的所有的属性。

## 基础属性

```python
>>> import angr, monkeyhex, claripy
>>> b = angr.Project('/bin/true')

>>> b.arch
<Arch AMD64 (LE)>
>>> b.entry
0x401410
>>> b.filename
'/bin/true'
>>> b.loader
<Loaded true, maps [0x400000:0x4004000]>
```

 - *arch*是`archinfo.Arch`对象的一个实例，代表了目标程序是为了哪种架构而编译的。更多信息在[这里](https://github.com/angr/archinfo/blob/master/archinfo/arch_amd64.py)。你经常会用到的是`arch.bits`，`arch.bytes` （它在[`Arch`类](https://github.com/angr/archinfo/blob/master/archinfo/arch.py)中使用`@property` 声明），`arch.name`, 和`arch.memory_endness`.
 - *entry*是二进制程序的入口点。
 - *filename*是程序的绝对路径。
 - *loader*是[cle.Loader](https://github.com/angr/cle/blob/master/cle/loader.py)的关于这个程序的一个实例。详细使用方法可以看[这里](./loading.md)。
 
## 分析与探索者

```python
>>> b.analyses
<angr.analysis.Analyses object at 0x7f5220d6a890>
>>> b.surveyors
<angr.surveyor.Surveyors object at 0x7f52191b9dd0>

>>> filter(lambda x: '_' not in x, dir(b.analyses))
['BackwardSlice',
 'BinDiff',
 'BoyScout',
 'BufferOverflowDetection',
 'CDG',
 'CFG',
 'DDG',
 'GirlScout',
 'SleakMeta',
 'Sleakslice',
 'VFG',
 'Veritesting',
 'XSleak']
>>> filter(lambda x: '_' not in x, dir(b.surveyors))
['Caller', 'Escaper', 'Executor', 'Explorer', 'Slicecutor', 'started']
```

`analyses` and `surveyors` 是Project中装载了所有分析者（Analyses）或者探索者对象（Surveyors）的容器。

分析者（Analyses）是可以从程序中获取一些信息的自定义的分析行为。
最常见的两种是`CFG`和`VFG`，`CFG`组织控制流图，`VFG`进行值－集合的分析。在[这里](./analyses.md)查看它们的详细用法以及如何完成你自己的分析者。

探索者（surveyors）是进行符号执行的的基础工具。
最常见的是`Explorer`，它可以搜索目标地址，同时避开你指定的地址。
关于探索者的详细说明可以看[这里](./surveyors.md)。
但是已经有了用于取代探索者的路径群（Path Groups）工具。

## 工厂对象

`b.factory`，像`b.analyses`和`b.surveyors`一样，是一个包含了很多有意思的东西的容器对象。它不是java概念中的工厂，它是所有能够产生重要angr类对象的函数的容器对象，是Project对象的一员。

```python
>>> import claripy # used later

>>> block = b.factory.block(addr=b.entry)
>>> block = b.factory.block(addr=b.entry, insn_bytes='\xc3')
>>> block = b.factory.block(addr=b.entry, num_inst=1)

>>> state = b.factory.blank_state(addr=b.entry)
>>> state = b.factory.entry_state(args=['./program', claripy.BVS('arg1', 20*8)])
>>> state = b.factory.call_state(0x1000, "hello", "world")
>>> state = b.factory.full_init_state(args=['./program', claripy.BVS('arg1', 20*8)])

>>> path = b.factory.path()
>>> path = b.factory.path(state)

>>> group = b.factory.path_group()
>>> group = b.factory.path_group(path)
>>> group = b.factory.path_group([path, state])

>>> strlen_addr = b.loader.main_bin.plt['strlen']
>>> strlen = b.factory.callable(strlen_addr)
>>> assert claripy.is_true(strlen("hello") == 5)

>>> cc = b.factory.cc()
```

- *factory.block* 是angr的lifter。给它传递一个地址将会举出程序在那个地址的基本代码块，并且返回一个angr的Block对象，可以用于获取对这个block的多种描述。下面会有进一步描述。
- *factory.blank_state* 返回一个除了应用传递给它的参数外，只进行了一些极少的初始化操作的SimState对象。关于程序的状态（state）在[这里](states.md)有进一步讨论。
- *factory.entry_state* 返回一个初始化在程序入口点状态的SimState对象。
- *factory.call_state* 返回一个初始化在使用给定的参数完成指定地址处的函数调用的SimState对象。
- *factory.full_init_state* 返回一个相似于`entry_state`的SimState对象。但是和入口点不同的是，程序计数器（PC）指向一个服务于动态装载器的SimProcedure并且在跳到入口点之前会调用每一个共享库的初始化器。
- *factory.path* 返回一个路径(Path)对象。既然路径只是对SimStates的轻量包装，你可以使用状态对象作为一个参数调用`path`然后得到一个对这一状态包装好的路径。在简单情况中，你传递给`path`的关键字参数将会传给`entry_state` 来创建一个用来包装的状态对象（state）。[这里](paths.md)有进一步讨论。
- *factory.path_group* 创建一个路径群！根本上来说，路径群是路径的智能列表，所以你可以传给它路径，状态或者是路径或状态的list作为参数。[这里](pathgroups.md)有进一步讨论。
- *factory.callable* 是非常酷的工具。Callables是可以调用任何二进制代码的FFI（foreign functions interface，远程函数接口）。[这里](structured_data.md)有进一步讨论。
- *factory.cc* 初始化一个调用惯例对象。它可以使用不同的参数或者甚至函数原型来初始化，并且可以作为参数传递给factory.callable或者factory.call_state来自定义参数和返回值以及返回地址在内存中的布局。[这里](structured_data.md)有进一步讨论。

### Lifter
通过*factory.block*来获取lifter。
这个方法有大量的可选参数，你可以阅读这份[文档](http://angr.io/api-doc/angr.html#module-angr.lifter)。
最下面一行是`block()`，给了你一个与基本代码块的接口。
你可以从块中得到像`.size`一样的属性，但是如果你想做一些有意思的事情，你需要更特殊点的描述。
使用`.vex`来得到[PyVEX IRSB](http://angr.io/api-doc/pyvex.html#pyvex.block.IRSB)或者`.capstone`来得到一个[Capstone block](http://www.capstone-engine.org/lang_python.html)。

### 文件系统选项
有一些参数可以传递给“状态”初始化函数，这将会影响文件系统的使用。包括`fs`， `concrete_fs`和`chroot`参数。

`fs`选项允许你传递一个文件名的字典作为参数来预先配置SimFile对象。这使得你可以做一些事情，比如设置一个文件大小的具体限制。

将`concrete_fs` 选项设置为`True`将会使angr谨慎使用磁盘上的文件。比如，当`concrete_fs`设置为`False`（默认值）时，如果模拟程序运行期间试图打开'banner.txt'，一个有符号内存支持的SimFile对象将会被创建并且模拟运行将会继续，就好像这个文件真实存在一样。当`concrete_fs`模式设置为`True`时，如果'banner.txt'存在一个有具体支持的SimFile对象将会被创建，减少了可能因为操作完全符号文件而导致的结果状态的激增。同时在`concrete_fs`模式下如果'banner.txt'不存在，如果试图打开'banner.txt'，SimFile对象不会被创建并且会返回一个错误码。但是，如果试图打开路径名以'/dev/'开头的文件，即便`concrete_fs`设置为`True`也不会成功打开具体的文件。

`chroot`选项允许你指定一个可选的根目录来使用`concrete_fs`选项。如果你正分析的程序使用绝对路径引用了其他文件，那这个选项会使事情变得很方便。比如，如果你正分析的程序试图打开'/etc/passwd'，你可以设置其chroot到你当前的工作路径，使得对'/etc/passwd'的访问将会读取'$CWD/etc/passwd'。


```python
>>> import simuvex
>>> files = {'/dev/stdin': simuvex.storage.file.SimFile("/dev/stdin", "r", size=30)}
>>> s = b.factory.entry_state(fs=files, concrete_fs=True, chroot="angr-chroot/")
```

这个例子将会创建一个限制了从stdin中最多读入30个符号字节的state，并且将会使所有对文件的引用都在新的root目录`angr-chroot`下被具体地解决。

在初始版本里值得注意的是：
在`entry_state` 和 `full_init_state`中起作用的`args` 和 `env`关键字参数分别是strings 或者 [claripy](./claripy.md) BV 对象的一个list和一个dict，它们可以代表一种具体和符号的字符。请阅读源码如果你想知道更多的话。


## 钩子

```python
>>> def set_rax(state):
...    state.regs.rax = 10

>>> b.hook(0x10000, set_rax, length=5)
>>> b.is_hooked(0x10000)
True
>>> b.unhook(0x10000)
>>> b.hook_symbol('strlen', simuvex.SimProcedures['stubs']['ReturnUnconstrained'])
```

钩子（Hook）可以对程序如何执行进行一些修改。
当你在确定的地址钩住了程序，那么不管程序在什么时候执行到这个地址，它都会执行你提供的python代码。
并且程序还会跳过`length`字节的原有指令再继续执行。
你可以不提供`length`参数来使程序从被钩住的地址继续执行而不跳过任何指令。

除了基础的函数，你可以使用一个`SimProcedure`对象来钩住地址，它是一个可以对程序执行进行更细粒度的控制的更复杂的系统。
提供`simuvex.SimProcedure`的子类（不是一个实例！）给相同的`hook`函数来实现这个功能。

`is_hooked`和`unhook`方法应该不用多说了。

`hook_symbol`是一个为目的不同的函数。你传递给它一个二进制文件中导入的函数名作为参数，而不是一个地址作为参数。
指向目标函数的内部指针（GOT）将会被指向SimProcedure或者你通过第三个参数指定的钩子函数替换。你也可以传递一个整形值来替换这个指针。
