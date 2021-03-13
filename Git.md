# GIT

官网文档：https://git-scm.com/docs

## 1、指令

### git init

创建一个空的git仓库或者重新初始化一个已存在的仓库。

```
git init [-q | --quiet] [--bare] [--template=<template_directory>]
	  [--separate-git-dir <git dir>] [--object-format=<format>]
	  [-b <branch-name> | --initial-branch=<branch-name>]
	  [--shared[=<permissions>]] [directory]
```

### git add

添加文件内容到索引（index），这个“索引”持有工作树内容的快照。并且它是用作下次提交的内容的快照。因此，在对工作树做出任何更改之后，且在运行提交命令之前，你必须使用 add 命令来添加任何新的或者修改过的文件到索引。	

```
git add [--verbose | -v] [--dry-run | -n] [--force | -f] [--interactive | -i] [--patch | -p]
	  [--edit | -e] [--[no-]all | --[no-]ignore-removal | [--update | -u]]
	  [--intent-to-add | -N] [--refresh] [--ignore-errors] [--ignore-missing] [--renormalize]
	  [--chmod=(+|-)x] [--pathspec-from-file=<file> [--pathspec-file-nul]]
	  [--] [<pathspec>…]
```

### git commit

记录仓库的变化，创建一个新的包含索引内容和给定的描述变化的log信息的内容的提交。

```
git commit [-a | --interactive | --patch] [-s] [-v] [-u<mode>] [--amend]
	   [--dry-run] [(-c | -C | --fixup | --squash) <commit>]
	   [-F <file> | -m <msg>] [--reset-author] [--allow-empty]
	   [--allow-empty-message] [--no-verify] [-e] [--author=<author>]
	   [--date=<date>] [--cleanup=<mode>] [--[no-]status]
	   [-i | -o] [--pathspec-from-file=<file> [--pathspec-file-nul]]
	   [-S[<keyid>]] [--] [<pathspec>…]
```

### git push

更新远程引用以及相关对象

```
git push [--all | --mirror | --tags] [--follow-tags] [--atomic] [-n | --dry-run] [--receive-pack=<git-receive-pack>]
	   [--repo=<repository>] [-f | --force] [-d | --delete] [--prune] [-v | --verbose]
	   [-u | --set-upstream] [-o <string> | --push-option=<string>]
	   [--[no-]signed|--signed=(true|false|if-asked)]
	   [--force-with-lease[=<refname>[:<expect>]] [--force-if-includes]]
	   [--no-verify] [<repository> [<refspec>…]]
```

### git remote

管理一组被跟踪的仓库

```
git remote [-v | --verbose]
#添加一个远程的名为<name>的在<url>上的仓库
git remote add [-t <branch>] [-m <master>] [-f] [--[no-]tags] [--mirror=(fetch|push)] <name> <url>
git remote rename <old> <new>
git remote remove <name>
git remote set-head <name> (-a | --auto | -d | --delete | <branch>)
git remote set-branches [--add] <name> <branch>…
git remote get-url [--push] [--all] <name>
git remote set-url [--push] <name> <newurl> [<oldurl>]
git remote set-url --add [--push] <name> <newurl>
git remote set-url --delete [--push] <name> <url>
git remote [-v | --verbose] show [-n] <name>…
git remote prune [-n | --dry-run] <name>…
git remote [-v | --verbose] update [-p | --prune] [(<group> | <remote>)…]
```



## 2、示例

### 建立本地仓库和远程仓库关联

```
#初始化仓库
git init

#添加远程仓库
git remote add origin https://github.com/jinguangshan-oss/appdemo.git

#添加文件到index
git add [--]<pathspec>

#如果误添加了文件使用git rm命令 --cache表示缓存 -r表示递归 .表示当前目录下所有文件
git rm --cached -r .

#提交文件到本地仓库
git commit

#更新远程仓库 --set-upstream表示设置上游分支（首次推送使用）
git push --set-upstream origin master


```

