# 安装angr

angr是一个python库，所以要使用它必须把它安装进你的python环境中。
它为python2而打造：对Py3k的支持在未来是可行的，但是我们现在有些犹豫现在是否要做出那样的承诺（欢迎pull requests！）。

我们强烈推荐使用[python虚拟环境](https://virtualenvwrapper.readthedocs.org/en/latest/)来安装和使用angr。
几种不同的angr依赖（z3，pyvex）需要从它们的原始库中fork原生代码库，如果你已经安装libz3或者libVEX，你肯定不想使用我们的覆盖官方的共享库。
总的来说，不要期待对从非虚拟环境中安装angr产生的问题的支持。

## 依赖

所有的python依赖都应该通过pip或者setup.py脚本处理。
但是你将会需要编译一些C代码从这里直到结束，所以你需要一个良好的编译环境以及python开发头文件。
在依赖安装过程中，你需要安装python库cffi，但是（至少在linux上）你还需要安装了你操作系统的libffi包它才可以运行。

在Ubuntu上，你需要：`sudo apt-get install python-dev libffi-dev build-essential virtualenvwrapper`


## 多数操作系统，全部\*nix系统

`mkvirtualenv angr && pip install angr` 在大多数情况下用来安装angr应该足够了， 因为angr被发布在Python包索引中。

Fish(shell)用户也可以使用[virtualfish](https://github.com/adambrenecki/virtualfish) 或者[virtualenv](https://pypi.python.org/pypi/virtualenv)包。
`vf new angr && vf activate angr && pip install angr`

如果使用这些失败了，你可以按照顺序通过安装下面来自https://github.com/angr的仓库（以及在它们的requirements.txt 文件中列出来的依赖包）：

- [claripy](https://github.com/angr/claripy)
- [archinfo](https://github.com/angr/archinfo)
- [pyvex](https://github.com/angr/pyvex)
- [cle](https://github.com/angr/cle)
- [simuvex](https://github.com/angr/simuvex)
- [angr](https://github.com/angr/angr)

## Mac OS X

在你使用`pip install angr`之前，你需要使用`pip install -I --no-use-wheel angr-only-z3-custom`重新编译我们fork来的z3库。

## Windows

在windows上你无法通过pip安装angr。
你必须单独安装它的所有组件。

Capstone在windows上很难安装。
你可能需要手动操作wheel文件来安装它，但是有时候它会使用一个不同于“capstone”的名字安装，所以如果如果发生了这样的事，你只需要（在安装它之后）在angr和archinfo的requirements.txt文件中移除Capstone就可以了。

如果你有足够的l33t编译环境可以在windows上编译Z3.
如果你没有，你需要从网上下个wheel文件。
在<https://github.com/Owlz/angr-Windows>可以下载预编译好的windows的wheel文件。

如果你从源代码编译z3，请确保你在使用包含了浮点支持的不稳定版本的z3。并且确保 `Z3PATH=path/to/libz3.dll`在你的环境变量里。

## 开发安装

我们使用脚本创建了一个仓库来使一切对于angr的开发者变得更容易。
你可以把angr设置为开发模式通过：

```bash
git clone https://github.com/angr/angr-dev
cd angr-dev
mkvirtualenv angr
./setup.sh
```

这克隆了所有的仓库并且把它们安装成了可编辑模式。
`setup.sh` 甚至可以为你创建一个PyPy虚拟环境，这使得其有了更快的性能和更低的内存占用。

你可以对不同的模块进行创建分支／编辑／重新编译操作，产生的变化会自动映射到你的虚拟环境中。

## 使用Docker安装

为了方便，我们只做了一个Docker镜像并且保证99%的可用性。
你可以通过docker来安装：

```bash
# install docker
curl -sSL https://get.docker.com/ | sudo sh

# pull the docker image
sudo docker pull angr/angr

# run it
sudo docker run -it angr
```

docker内外的文件同步作为留给使用者的一个练习（提示：看看 `docker -v`）

# 疑难解决

## libgomp.so.1: version `GOMP_4.0' not found

这个错误表明在预编译版本的`angr-only-z3-custom`和安装版本的`libgomp`存在不兼容问题。需要重新编译Z3.你可以执行：

```bash
pip install -I --no-use-wheel angr-only-z3-custom
```
## Can't import mulpyplexer

在安装mulpyplexer有时会有一些问题。执行`pip install --upgrade 'git+https://github.com/zardus/mulpyplexer'` 可以解决这个问题。

## Can't import angr because of capstone

有时capstone没有被正确安装。重新安装capstone可以解决这个问题：

```bash
pip install -I --no-use-wheel capstone
```

## Claripy and z3

Z3编译起来很奇怪。有时它会无缘无故的完全失败，提示由于一些文件或文件夹不存在而无法创建对象文件。你只需要重新编译：

```bash
pip install -I --no-use-wheel angr-only-z3-custom
```

## No such file or directory: 'pyvex_c'

你在使用12.04吗？如果是，请升级吧！
你也可以试试升级pip（`pip install -U pip`），也许也可以解决这个问题。