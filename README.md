# 如何使用angr

这是一份对angr文档的收集。通过阅读这份文档，你可以成为一个angr专业人员并且可以随意操作二进制文件。

我们尽力让angr易于上手——我们的目标是创建一个对用户友好的二进制分析工具套件，让用户可以在iPython中通过一系列命令操作二进制文件。但是遗憾的是二进制分析是一件复杂的事情，这使得angr也变得复杂。这篇文档致力于通过提供对angr及其设计的解释和探索来解决这个问题。

# 开始

安装说明可以看[这里](./INSTALL.md)。

为了深入探索angr的能力，你可以从它的[顶层方法](./docs/toplevel.md)入手，或者阅读[这篇总览](./docs/overview.md)。

这篇文档支持搜索功能的html版本放在[docs.angr.io](http://docs.angr.io/)，HTML API可以查看[angr.io/api-doc](http://angr.io/api-doc/)。

# 引用angr

如果你想要在学术工作中使用angr，请引用这些论文：

```
@article{shoshitaishvili2016state,
  title={SoK: (State of) The Art of War: Offensive Techniques in Binary Analysis},
  author={Shoshitaishvili, Yan and Wang, Ruoyu and Salls, Christopher and Stephens, Nick and Polino, Mario and Dutcher, Andrew and Grosen, John and Feng, Siji and Hauser, Christophe and Kruegel, Christopher and Vigna, Giovanni},
  booktitle={IEEE Symposium on Security and Privacy},
  year={2016}
}

@article{stephens2016driller,
  title={Driller: Augmenting Fuzzing Through Selective Symbolic Execution},
  author={Stephens, Nick and Grosen, John and Salls, Christopher and Dutcher, Andrew and Wang, Ruoyu and Corbetta, Jacopo and Shoshitaishvili, Yan and Kruegel, Christopher and Vigna, Giovanni},
  booktitle={NDSS},
  year={2016}
}

@article{shoshitaishvili2015firmalice,
  title={Firmalice - Automatic Detection of Authentication Bypass Vulnerabilities in Binary Firmware},
  author={Shoshitaishvili, Yan and Wang, Ruoyu and Hauser, Christophe and Kruegel, Christopher and Vigna, Giovanni},
  booktitle={NDSS},
  year={2015}
}
```

# 支持

如果想要获取关于angr的帮助，你可以通过：

- 邮件： angr@lists.cs.ucsb.edu
- IRC频道([freenode](https://freenode.net/))：**#angr**
- 在github对应仓库上打开一个issue

# 深入阅读
这篇[论文](https://www.cs.ucsb.edu/~vigna/publications/2016_SP_angrSoK.pdf)解释了angr的一些内部原理，算法和使用到的技术，你可以阅读它来进一步理解在angr运行中会发生什么。
