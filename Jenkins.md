# Jenkins

## 1、安装

​	

```
#安装
sudo wget -O /etc/yum.repos.d/jenkins.repo https://pkg.jenkins.io/redhat-stable/jenkins.repo
sudo rpm --import https://pkg.jenkins.io/redhat-stable/jenkins.io.key
sudo yum upgrade
sudo yum install jenkins
sudo systemctl daemon-reload

#修改Jenkins配置文件
	#添加java安装路径
	vi /etc/init.d/jenkins（找到candidates，后面添加手动安装的java路径/usr/local/jdk-8/jdk1.8.0_281/bin/java）
	#修改用户
	vi /etc/sysconfig/jenkins（修改此项为启动Jenkins守护进程所用Unix用户账号：JENKINS_USER="root"，端口号JENKINS_PORT="8001"）
	
#重载系统文件
systemctl daemon-reload

#启动
sudo systemctl start jenkins

#检查
sudo systemctl status jenkins
（从结果不难看出是否正常运行：Active: active (running) since Sat 2021-01-30 15:03:42 CST; 4min 44s ago）

#停止和重启
sudo systemctl stop jenkins
sudo systemctl restart jenkins

```

## 2、安装后设置向导

### a、解锁jenkins

​		当你第一次进入Jenkins实例，看到解锁Jenkins页面，你将被要求用一个自动生成的密码来解锁它。

- 用浏览器输入地址：http://8.136.198.25:8001/
- 将Jenkins所在服务器文件内容/var/lib/jenkins/secrets/initialAdminPassword填入密码栏
- 点击继续

### b、用插件定制jenkins

​		在解锁Jenkins后，定制Jenkins页面显现出来，在这个页面你可以安装一些有用的插件作为初始化步骤的一部分。选择其中一个选项

- **Install suggested plugins** - to install the recommended set of plugins, which are based on most common use cases.
- **Select plugins to install** - to choose which set of plugins to initially install. When you first access the plugin selection page, the suggested plugins are selected by default.

### c、创建第一个管理员用户

- ​	当创建第一个管理员用户页面显现出来的时候，在这些散落的字段上面指定你管理员用户的详情。
- ​	当J**Jenkins is ready**页面显示出来的时候，点击**Start using Jenkins**.
- ​	如果需要，用你刚刚创建的管理员用户凭证登录Jenkins，然后就就可以开始使用Jenkins了

ps：

user：admin

pass：admin123

name：jinguangshan

mail：jinguangshan2021@163.com

ps：设置jenkins语言 https://blog.csdn.net/nklinsirui/article/details/89576475

### d、设置Jenkins环境变量

登录Jenkins，进入到下位置：dashboard——Manage Jenkins——Configure System——Global properties，添加：

```
JAVA_HOME
/usr/local/jdk-8/jdk1.8.0_281

MAVEN_HOME
/usr/local/apache-maven-3.6.3

PATH+EXTRA
$MAVEN_HOME/bin
```

也可以不设置环境变量，通过设定全局工具（dashboard——Manage Jenkin——Global Tool Configuration——Add Jdk&&Add Maven）+ 编辑Jenkinsfile，

```
pipeline {
    agent any
    tools {
        maven 'Maven 3.6.3'
        jdk 'jdk8'
    }
}
```



## 3、Jenkins Pipeline

下面开始通过使用Jenkins来实现持续集成/持续交付（CD/DI）概念。

### Pipeline概念

Jenkins Pipeline(简称"Pipeline")是一套在Jenkins中支持实现和集成"持续交付通道"的的插件。

持续交付通道（CD)是你将软件从版本控制直接传递给用户和客户这一自动化操作过程的表达，你的软件的每一个变化（在版本控制中发生过的提交），在发布过程中将经历复杂的处理。这项处理包括以一种可靠的，可重复的方式构建软件，以及通过多个测试和部署阶段来推进软件的构建。

Pipeline提供了一系列工具通过Pipeline domain-specific language（DSL）语法，将简单到复杂的“交付通道”建模成“代码”

Pipeline的定义被写进一个文本文件（称作Jenkinsfile），这个文件可以被提交到一个项目的源代码管理仓库。这是Pipeline as code（通道即代码）的基础，把CD Pipeline当成应用的一部分，以像其他代码一样进行版本控制和审查。

然而定义Pipeline的语法，无论在Web UI或者使用Jenkinsfile都是一样的，但在Jenkinsfile中定义Pipeline并且从源码控制中检出它 通常被认为是最好的惯例。

### 声明式 vs 脚本式 Pipeline语法

一个Jenkinsfile可以通过两种语法编写——声明式，脚本式，这两种语法在基础构造上是不同的，声明式通道更接近Jenkins Pipeline的下列特性：

- 提供比脚本式Pipeline语法更丰富的语法特性
- 并且在设计上使读写Pipeline代码更容易

### 声明式Pipeline语法（Declarative Pipeline syntax）

在声明式语法中，这个"pipeline"块定义了所有待完成工作，这些工作贯穿你的整个pipeline

```
pipeline {
    agent any 
    stages {
        stage('Build') { 
            steps {
                // 
            }
        }
        stage('Test') { 
            steps {
                // 
            }
        }
        stage('Deploy') { 
            steps {
                // 
            }
        }
    }
}
```

### 脚本式Pipeline语法（Scripted Pipeline syntax）

在脚本式语法中，一个或者更多的"node块"做着核心的做工作，这些工作贯穿整个pipeline中

```
node {  
    stage('Build') { 
        // 
    }
    stage('Test') { 
        // 
    }
    stage('Deploy') { 
        // 
    }
}
```



## 4、使用Jenkins

### 新建一个项目

Dashboard——New Item——输入项目名称，选择pipeline（中文社区插件翻译为流水线）

### 设置项目

#### General（通用）

​		//Todo

#### Build Trigger（构建触发器）

​		//Todo

#### Advanced Project Options（高级项目选项）

​		//Todo

#### Pipeline（管道）

​		两种方式设置Pipeline Definition

##### a、Web UI定义（Pipeline script）

​		直接在Script框中写入pipeline定义

##### b、SCM定义（Pipeline script from SCM）

设置SCM

​	SCM：Git

​		设置Git Repositories

​			Repository URL：https://github.com/qiaozhi-oss/simple-java-maven-app.git

​			Credentials：添加用户名密码证书

​		设置Git Branches to build

​			Branch Specifier (blank for 'any')：*/master

​		设置Git Repository browser

​			Repository browser：（Auto）

设置Script Path

​	Script Path：jenkins/Jenkinsfile

###### c、附录：Jenkinsfile内容

```
pipeline {
    agent any
    tools {
        maven 'Maven 3.6.3'
        jdk 'jdk8'
    }
    stages {
        stage ('Initialize') {
            steps {
                echo "JAVA_HOME = ${JAVA_HOME}"
                echo "MAVEN_HOME = ${MAVEN_HOME}"
            }
            post {
                success {
                    echo "#######################Initialize Success!#######################"
                }
            }
        }

        stage ('Clean') {
            steps {
                sh 'mvn clean'
            }
            post {
                success {
                    echo "#######################Clean Success!#######################"
                }
            }
        }

        stage ('Build') {
            steps {
                sh 'mvn install'
            }
            post {
                success {
                    echo "#######################Build Success!#######################"
                }
            }
        }
        
        stage ('Runtime') {
            steps{
                sh "chmod +x -R ${env.WORKSPACE}"
                sh './jenkins/appdemo/deliver.sh'
            }
            post {
                success {
                    echo "#######################Application Started!#######################"
                }
            }
        }
    }
}
```

###### d、附录：deliver.sh内容

```
#!/usr/bin/env bash
#设置变量：摘取pom文件project.name,project.version
NAME=`mvn help:evaluate -Dexpression=project.artifactId | grep "^[^\[]"`
VERSION=`mvn help:evaluate -Dexpression=project.version | grep "^[^\[]"`
echo "JAR NAME : ${NAME}-${VERSION}.jar"

#杀死已存在进程：if [ -n "$xxx" ]用于判断xxx变量非空  fi为if语句的结束,相当于end if
pid=`ps -ef | grep ${NAME}-${VERSION}.jar|grep -v grep|awk '{print $2}'`
if [ -n "$pid" ]
then
  kill -9 $pid
  echo "${NAME}-${VERSION}.jar pid = ${pid} has been Killed"
fi


#设置JENKINS_SERVER_COOKIE：由于pipeline退出时候会kill掉其子进程，遵循规则——kill process only in case if JENKINS_NODE_COOKIE and BUILD_ID are unchanged
echo "before modification:  BUILD_ID = ${BUILD_ID}  JENKINS_SERVER_COOKIE = ${JENKINS_NODE_COOKIE}"
#BUILD_ID=keepmealive ps:针对自由风格项目而非pipeline的项目可通过修改此变量，防止被ProcessTreeKiller kill掉
JENKINS_NODE_COOKIE=keepmealive
echo "after modification:   BUILD_ID = ${BUILD_ID}  JENKINS_SERVER_COOKIE = ${JENKINS_NODE_COOKIE}"

#后台jar包启动,并将日志输出到application.log 文件
nohup java -Xms800m -Xmx800m -XX:MetaspaceSize=256m -XX:MaxMetaspaceSize=512m -XX:MaxNewSize=512m -jar ./target/${NAME}-${VERSION}.jar 1>/var/lib/jenkins/workspace/application.log 2>&1 &

#打印启动成功日志
echo "${NAME}-${VERSION}.jar start successful"
```



## 5、Jenkins运行springboot

问题1、jar包非后台方式启动成功后Jenkins一直在构建中

解决：java -jar xxx.jar 方式启动会阻塞当前进程，采用 nohup java -jar xxx.jar >/dev/null 2>&1 &



问题2、通过jar包后台启动的springboot项目，在jenkins pipeline退出时被ProcessTreeKiller当成pipeline子进程kill掉

解决：在shell脚本中加入 JENKINS_NODE_COOKIE=keepmealive，位置在java -jar 之前

​		ps：如果是自由风格的项目则通过BUILD_ID=keepmealive ，来避免进程被kill

参考资料：

​		jenkins Jira： https://issues.jenkins.io/browse/JENKINS-28182

​		jenkins 维基百科：https://wiki.jenkins.io/display/JENKINS/ProcessTreeKiller

​		博客：https://blog.csdn.net/nklinsirui/article/details/80307979



问题3、unable to access 'https://github.com/jinguangshan-oss/appdemo.git/': Empty reply from server

​	解决：将https改为 git ，例如： git://github.com/jinguangshan-oss/appdemo.git/

​	参考资料：https://blog.csdn.net/qq_42037180/article/details/112465841



问题4、git 拉取下来的文件没有执行权限（当前用户root）

​	解决：

```
stage('Test') {
    steps {
        sh "chmod +x -R ${env.WORKSPACE}"#执行工作空间脚本前先赋予执行权限
        sh './jenkins/test.sh'
    }
}
```

​	参考资料：https://stackoverflow.com/questions/43372035/permission-denied-when-executing-the-jenkins-sh-pipeline-step