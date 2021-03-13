# maven

## 1、安装（centos）

### a、下载&&解压

```
wget http://mirrors.hust.edu.cn/apache/maven/maven-3/3.6.3/binaries/apache-maven-3.6.3-bin.tar.gz
tar -zxvf  apache-maven-3.6.3-bin.tar.gz
```

### c、配置环境变量

```
vi /etc/profile
#在文档上加入如下内容
export MAVEN_HOME=/usr/local/apache-maven-3.6.3
export PATH=$MAVEN_HOME/bin:$PATH
#加上此语句可以清除$PATH路径重复问题
export PATH=$(echo $PATH | tr : "\n"| sort | uniq | tr "\n" :)
```

### d、刷新环境变量

```
source /etc/profile
```

## 2、使用

### a、语法 mvn [options] [<goal(s)>] [<phase(s)>]

运行maven的语法如下：

```
mvn [options] [<goal(s)>] [<phase(s)>]
```

所有选项都记录在内置的帮助中，你可以通过如下命令访问

```
mvn -h
```

对于一个新构建的项目的“生成所有打包数据和文档站点，以及将之发布到一个仓库管理器”可以通过以下命令完成

```
mvn clean deploy site-deploy #clean deploy sit-deploy分别对应着生命周期的三个阶段
```



### b、选项 [options]

```

usage: mvn [options] [<goal(s)>] [<phase(s)>]

Options:
 -am,--also-make                        If project list is specified, also
                                        build projects required by the
                                        list
 -amd,--also-make-dependents            If project list is specified, also
                                        build projects that depend on
                                        projects on the list
 -B,--batch-mode                        Run in non-interactive (batch)
                                        mode (disables output color)
 -b,--builder <arg>                     The id of the build strategy to
                                        use
 -C,--strict-checksums                  Fail the build if checksums don't
                                        match
 -c,--lax-checksums                     Warn if checksums don't match
 -cpu,--check-plugin-updates            Ineffective, only kept for
                                        backward compatibility
 -D,--define <arg>                      Define a system property
 -e,--errors                            Produce execution error messages
 -emp,--encrypt-master-password <arg>   Encrypt master security password
 -ep,--encrypt-password <arg>           Encrypt server password
 -f,--file <arg>                        Force the use of an alternate POM
                                        file (or directory with pom.xml)
 -fae,--fail-at-end                     Only fail the build afterwards;
                                        allow all non-impacted builds to
                                        continue
 -ff,--fail-fast                        Stop at first failure in
                                        reactorized builds
 -fn,--fail-never                       NEVER fail the build, regardless
                                        of project result
 -gs,--global-settings <arg>            Alternate path for the global
                                        settings file
 -gt,--global-toolchains <arg>          Alternate path for the global
                                        toolchains file
 -h,--help                              Display help information
 -l,--log-file <arg>                    Log file where all build output
                                        will go (disables output color)
 -llr,--legacy-local-repository         Use Maven 2 Legacy Local
                                        Repository behaviour, ie no use of
                                        _remote.repositories. Can also be
                                        activated by using
                                        -Dmaven.legacyLocalRepo=true
 -N,--non-recursive                     Do not recurse into sub-projects
 -npr,--no-plugin-registry              Ineffective, only kept for
                                        backward compatibility
 -npu,--no-plugin-updates               Ineffective, only kept for
                                        backward compatibility
 -nsu,--no-snapshot-updates             Suppress SNAPSHOT updates
 -ntp,--no-transfer-progress            Do not display transfer progress
                                        when downloading or uploading
 -o,--offline                           Work offline
 -P,--activate-profiles <arg>           Comma-delimited list of profiles
                                        to activate
 -pl,--projects <arg>                   Comma-delimited list of specified
                                        reactor projects to build instead
                                        of all projects. A project can be
                                        specified by [groupId]:artifactId
                                        or by its relative path
 -q,--quiet                             Quiet output - only show errors
 -rf,--resume-from <arg>                Resume reactor from specified
                                        project
 -s,--settings <arg>                    Alternate path for the user
                                        settings file
 -t,--toolchains <arg>                  Alternate path for the user
                                        toolchains file
 -T,--threads <arg>                     Thread count, for instance 2.0C
                                        where C is core multiplied
 -U,--update-snapshots                  Forces a check for missing
                                        releases and updated snapshots on
                                        remote repositories
 -up,--update-plugins                   Ineffective, only kept for
                                        backward compatibility
 -v,--version                           Display version information
 -V,--show-version                      Display version information
                                        WITHOUT stopping build
 -X,--debug                             Produce execution debug output

```



### c、目标 [<goal(s)>]

​		//Todo 根据所用的阶段定义

### d、阶段 [<phase(s)>]

#### 生命周期 clean 所对应的阶段

- pre-clean
- clean
- post-clean

#### 生命周期 default 所对应的阶段

- validate
- initialize
- generate-sources
- process-sources
- generate-resources
- process-resources       #复制并处理资源文件，至目标目录，准备打包。
- compile                          #编译项目的源代码
- process-classes,
- generate-test-sources
- process-test-sources
- generate-test-resources
- process-test-resources #复制并处理资源文件，至目标测试目录。
- test-compile                   #编译测试源代码
- process-test-classes
- test                                  #使用单元测试框架运行测试，这些测试代码不会被打包或部署
- prepare-package
- package                           #接受编译好的代码，打包成可发布的格式，如JAR。
- pre-integration-test
- integration-test
- post-integration-test
- verify
- install                              #将包安装至本地仓库，以让其它项目依赖。
- deploy                            #将最终的包复制到远程的仓库，以让其它开发人员与项目共享或部署到服务器上运行

#### 生命周期 site 所对应的阶段

- pre-site
- site
- post-site
- site-deploy

## 3、插件

### Apache Maven Help Plugin

​		Maven Help插件用于获取一个项目或者系统的相关信息。它可以被用来获取一个特定插件的描述，包括带有参数和组件需求的插件目标、当前构建的有效设置和有效POM、以及用于当前正在构建项目的配置文件。

​		Help插件有7个目标

- [help:active-profiles](http://maven.apache.org/plugins/maven-help-plugin/active-profiles-mojo.html) lists the profiles which are currently active for the build.

- [help:all-profiles](http://maven.apache.org/plugins/maven-help-plugin/all-profiles-mojo.html) lists the available profiles under the current project.

- [help:describe](http://maven.apache.org/plugins/maven-help-plugin/describe-mojo.html) describes the attributes of a Plugin and/or a Mojo (Maven plain Old Java Object).

- [help:effective-pom](http://maven.apache.org/plugins/maven-help-plugin/effective-pom-mojo.html) displays the effective POM as an XML for the current build, with the active profiles factored in. If `verbose`, a comment is added to each XML element describing the origin of the line.

- [help:effective-settings](http://maven.apache.org/plugins/maven-help-plugin/effective-settings-mojo.html) displays the calculated settings as an XML for the project, given any profile enhancement and the inheritance of the global settings into the user-level settings.

- [help:evaluate](http://maven.apache.org/plugins/maven-help-plugin/evaluate-mojo.html) evaluates Maven expressions given by the user in an interactive mode.

  在交互模式下计算用户给定的Maven表达式

  e.g. ：

  ```
  NAME=`mvn help:evaluate -Dexpression=project.name | grep "^[^\[]"`
  VERSION=`mvn help:evaluate -Dexpression=project.version | grep "^[^\[]"`
  #打印
  echo "Path : ./target/${NAME}-${VERSION}.jar"
  ```

  

- [help:system](http://maven.apache.org/plugins/maven-help-plugin/system-mojo.html) displays a list of the platform details like system properties and environment variables.