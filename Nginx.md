# Nginx

## 一、入门

### 1、nginx安装（centos8）

- 安装依赖包

​			centos：yum -y install pcre-devel openssl openssl-devel

- 下载解压nginx安装包

​			下载地址：http://nginx.org/en/download.html

​			tar -zxvf nginx-1.19.6.tar.gz

- 执行configure

​			cd到解压后的目录，执行./configure

- 编译&&安装

​			cd到解压后的目录，执行make && make install

- 启动

​			/usr/local/nginx/sbin -c /usr/local/nginx/conf/nginx.conf



### 2、Starting, Stopping, and Reloading Configuration

#### 	a、启动指令

​			nginx -c 

#### 	b、启动后的控制指令

​			nginx -s signal

​			Where *signal* may be one of the following:

​			stop——fast shutdown

​			quit——graceful shutdown

​			reload——reloading the configuration file

​			reopen——reopening the log files

#### 	c、nginx -s reload命令，对应nginx执行过程

- 主进程一旦收到重新加载配置的信号，便对新的配置文件进行语法检查，并尝试应用新配置
- 一旦成功。主进程开启一个新的工作进程并通知关闭旧的工作进程，旧工作进程收到通知，停止接收新的请求，继续服务当前正在处理中的请求，直到这些请求全部处理完成，旧工作进行退出关闭。
- 一旦失败，主进程回退已发生的变更，并继续使用旧的配置

​			

### 3、Configuration File’s Structure

#### a、简单指令

​		由被空格分隔的名称和参数组成，以分号（；）结尾

#### b、块指令

​		和简单指令结构相似，名称和参数由空格分隔，不同的是结尾部分是由一个被花括号（{}）包裹的指定集合组成。

​		块指令可以包含其他指令在花括号里面（{}），这些被包含的指令被称作“上下文”

​		配置文件中不在任何上下文中的指令被认为是在主“上下文”中

### 4、Serving Static Content

​		通过修改配置文件，并设置http块指令——server块指令——location块指令，基于本地文件系统，实现静态文件服务（比如图片，html）。

- 配置文件可能含有多个server，这些server通过所监听端口号和服务名区分。
- 当nginx选择一个server处理request的时候，它将request请求头中的URI和location指令的参数进行测比，
- 如果匹配，则该URI被添加到root指令指定的path后面，组成在本地文件系统中的请求path
- 如果有多个匹配的location，nginx选择带有最长前缀参数的一个
- 如果除'"/"前缀参数的location外，其他所有location均不匹配，则nginx选择此带有"/"前缀的location

	http {
	    include       mime.types;
	    default_type  application/octet-stream;
	    sendfile        on;
	    keepalive_timeout  65;
	    server{
	        listen       80;
	        server_name  localhost;
	        location / {
	            root /data/www;
	        }
	        location /images/ {
	            root /data;
	        }
	    }
	}
### 5、Setting Up a Simple Proxy Server

​		nginx一项频繁被使用的用途是代理服务，作为代理服务，nginx接受请求，递送请求到被代理的服务，最后从取回响应，并将响应发送到客户端

- 首先，通过添加一个或多个server块指令到nginx配置文件，定义一个被代理的服务。
- 然后，在代理服务的location块指令下设置proxy_pass指令，该指定参数定义了被代理服务的协议，地址，端口号
- 最后，指定nginx -s reload重载已更新的配置。

```
server {
    listen 8080;
    root /data/up1;

    location / {
    }
}
server {
	listen 80;
    location / {
        proxy_pass http://localhost:8080;
    }

    location ~ \.(gif|jpg|png)$ {
    	root /data/images;
	}
}
```



### 6、Setting Up FastCGI Proxying

​		nginx can be used to route requests to FastCGI servers which run applications built with various frameworks and programming languages such as PHP



## 二、高级

### 1、Basic Functionality（基本功能）

#### 1.1、Controlling NGINX Processes at Runtime

​		nginx有一个主进程和一个以上的工作进程，如果开启缓存，则缓存加载进程和缓存管理进程也在启动时候运行。

##### a、主进程

​		主进程和主要作用是读取和评测配置文件，以及维护工作进程。

##### b、工作进程

​		工作进程做实际的请求处理。nginx依靠操作系统依赖机制在工作进程之间分发请求。工作进程的个数由配置文件的worker_processes指令定义，可以设置为一个数，也可以配置为根据cup可用内核数自动调整

##### c、控制nginx

​		为了重新加载配置文件，你可以通过stop 和 start命令重启nginx，或者给主进程发送信号，这个信号可以通过执行一个带有 -s 参数的nginx命令发送。

```
nginx -s <SIGNAL>

where <SIGNAL> can be one of the following:
	quit – Shut down gracefully
	reload – Reload the configuration file
	reopen – Reopen log files
	stop – Shut down immediately (fast shutdown)
```

#### 1.2、Creating NGINX Plus and NGINX Configuration Files

##### a、Feature-Specific Configuration Files

​		为了使配置文件更容易维护，官方推荐将单个配置文件拆分成按特征指定的配置文件集合，这个文件集合存放在/etc/nginx/conf.d目录，并且用include指令引用这些按特征指定的文件的内容。

```
include conf.d/http;
include conf.d/stream;
include conf.d/exchange-enhanced;
```

##### b、Contexts

​		几个顶层指令，被作为Contexts提及，一起将应用于不同交易类型的指令进行分组

```
events – General connection processing
http – HTTP traffic
mail – Mail traffic
stream – TCP and UDP traffic
```

##### c、Virtual Servers

- ​	在每个交易处理的上下文（traffic‑handling Contexts），你有多个server块指令控制着请求的处理。
- ​	对于HTTP交易，每个server指令在特定域名或者IP地址上控制着的资源请求的处理，在server指令上下文中的多个location上下文定义了如何处理特定的URI集合。
- ​	对于mail和TCP/UDP交易，每个server指令控制着到达特定TCP端口或UNIX套接字的交易的处理。

##### d、Inheritance

​	通常来讲，一个被另外一个上下文（父上下文）包裹的子上下文，继承着父级包含的指令设置。这样一些指令就可以在多级上下文中起作用，在这个场景下，你可以通过在子上下文中包含指令来重写从父上下文中继承而来的设置。例如 root /data/www 可以写在父级server上，子级可以通过包含root /data/www-1 进行重写。

### 2、Load Balancer（负载均衡）

#### a、HTTP Load Balancing

##### a1、指令定义

```
http {
    upstream backend {
        server backend1.example.com;
        server backend2.example.com;
        server 192.0.0.1 backup;
    }
    
    server {
        location / {
            proxy_pass http://backend;
        }
    }
}
```

##### a2、负载均衡方式

###### Round Robin

所有请求被平均地分发到这些服务，服务权重被考虑在内。这个方式被默认采用

```
upstream backend {
   # no load balancing method is specified for Round Robin
   server backend1.example.com weight=5;
   server backend2.example.com weight=3;
}
```



###### least Connection

一个请求被发送到带有最少活跃连接数的服务，服务权重也被考虑在内。

```
upstream backend {
    least_conn;
    server backend1.example.com;
    server backend2.example.com;
}
```



###### Ip Hash

请求发向的服务由客户的IP地址决定。既然这样，要么IPV4地址的前三个字节，要么整个IPV6地址都被用来计算hash值。这种方法保证来自相同IP地址的请求被送向相同的服务，除非这个服务不可用。

```
upstream backend {
    ip_hash;
    server backend1.example.com;
    server backend2.example.com;
}
```

如果其中一个服务需要被临时从负载均衡循环中移除，它可以被down 参数表示。本来将要被这个服务处理的请求将被自动地发送到本组的下一个服务。

```
upstream backend {
    server backend1.example.com;
    server backend2.example.com;
    server backend3.example.com down;
}
```



###### Generic Hash

请求发向的服务由一个客户定义的key决定，这个key可以是一个文本字符串，变量，或者一个组合。例如这个key可以是一个成对的源IP地址和端口号，或者下面示例中的URI

```
upstream backend {
    hash $request_uri consistent;
    server backend1.example.com;
    server backend2.example.com;
}
```

hash指令上的consistent参数开启一致性has负载均衡，基于用户定义的key的hash值，请求被平均地分发向所有的upstream服务。如果一个upstream服务从upstream组上被添加或移除，那么在负载均衡缓存服务或者其他应用状态累计的情况下，只有少数的几个keys将被重新映射以最小化缓存丢失



###### Least Time（Nginx Plus Only）

对于每个请求，Nginx Plus选择带有最少平均延迟和最少活跃连接数的那个服务。这个最少平均延的计算基于least_time指令的如下哪个参数被包含：

- header——从服务上收到第一个字节的时候

- last_byte——从服务上收到完整响应的时间

- last_byte inflight——从服务上收到完整响应的时间，考虑到不完整的请求

  ```
  upstream backend {
      least_time header;
      server backend1.example.com;
      server backend2.example.com;
  }
  ```

  

###### Random

每个请求被发向一个随机选择的服务，如果two参数被指定，首先Nginx根据服务权重随机选择两个服务，并且用指定的方式选择这些服务中的其中一个。

```
upstream backend {
    random two least_time=last_byte;
    server backend1.example.com;
    server backend2.example.com;
    server backend3.example.com;
    server backend4.example.com;
}
```

##### a3、服务权重

默认情况下，Nginx利用Round Robin方式根据服务的权重，在同一组的服务之间分发请求。server指令中的weight参数设置了一个服务的权重，默认权重是1。

```
upstream backend {
    server backend1.example.com weight=5;
    server backend2.example.com;
    server 192.0.0.1 backup;
}
```

这这个例子中backend1.example.com权重是5，其他两个权重是1，但是IP地址为192.0.0.1的服务被标记为backup服务并且不会接受请求除非其他两个服务都不可用。利用这个权重配置，每6个请求，5个被发向backend1.example.com，剩下的1个被发向192.0.0.1。

##### a4、服务慢启动

服务的慢启动特性可以防止一个最近启动的服务因连接过多而过载。这可能造成服务超时并造成服务再次被标记为失败。

在Nginx Plus，慢启动让一个upstream服务在它恢复或变成可用之后，从0到其标称值，逐渐恢复其权重。这可以借助server指令的slow_start参数来实现。

```
upstream backend {
    server backend1.example.com slow_start=30s;
    server backend2.example.com;
    server 192.0.0.1 backup;
}
```

这个时间值（这里设置的30s）设置Nginx Plus将服务的连接数提升到一个完整值的时间

注意如果在一个upstream组内只有一个服务，那么server指令的max_fails,fail_timeout,以及slow_start参数都将被忽略，并且这个服务永远不会被认定不可用。

##### a5、开启会话持久性

会话持久性意味着Nginx Plus识别用户会话并且将一个给定会话中的所有请求路由到相同的上游服务

Nginx Plus支持三种会话持久化方式。这些方式都通过sticky指令设置。

###### Sticky cookie（绑定cookie）

Nginx Plus添加一个会话cookie 到上游组中的第一个response，并且标识发送这个响应的服务。客户端的下一个请求包含这个cookie的值    并且Nginx Plus将这个请求路由到响应第一个请求的上游服务。

```
upstream backend {
    server backend1.example.com;
    server backend2.example.com;
    sticky cookie srv_id expires=1h domain=.example.com path=/;
}
```

在这个示例中

- srv_id设置了cookie的名称
- 可选参数expires设置了浏览器保存cookie的时间（这里是1小时）
- 可选参数domain定义了cookie设置的域
- 可选参数path定义了cookie设置的路径

###### Sticky route（绑定route）

当Nginx Plus收到第一个请求的时候，它分配一个“route”到这个客户端。所有后续的请求都将和server指令的route参数进行对比，以识别请求被哪个服务所代理。route信息从cookie或request URI中获取。

```
upstream backend {
    server backend1.example.com route=a;
    server backend2.example.com route=b;
    sticky route $route_cookie $route_uri;
}
```

###### Sticky learn（绑定learn）

Nginx Plus首先通过检查请求和响应查找会话标识符。然后Nginx Plus“学习”哪个上游服务对应哪个会话标识符：通常，这些标识符通过一个Http cookie传递。如果一个请求包含一个被“学习”过的请求标识符，Nginx Plus将这个请求转发到相对应的服务。

```
upstream backend {
   server backend1.example.com;
   server backend2.example.com;
   sticky learn
       create=$upstream_cookie_examplecookie
       lookup=$cookie_examplecookie
       zone=client_sessions:1m
       timeout=1h;
}
```

##### a6、限制最大连接数

使用Nginx Plus，通过使用max_conns参数指定一个最大数字，可以限制一个上游服务的连接数。

如果已经达到max_conns，后续请求被放置到一个队列当中以等待进一步处理，前提是这个queue也被包含在内，这个queue设置了可以同时存在于这个队列中的请求的最大数。

```
upstream backend {
    server backend1.example.com max_conns=3;
    server backend2.example.com;
    queue 100 timeout=70;
}
```

如果在通过可选参数timeout设置的超时时间内，队列已经填满或者上游服务不能被选择，客户端将受到一个错误。

注意如果存在 在其他工作进程中打开的空闲且保持存活的连接，max_conns限制将被忽视。作为结果，在一个多工作进程共享内存的配置当中，服的连接总数可能超出max_conns的值。

##### a7、健康检查

Nginx可以持续检查你的Http上游服务，消除失败的服务，并且优雅地将恢复的服务添加到负载均衡组。

##### a8、多工作进程之间共享数据

###### Zone介绍

如果upstream块不包含一个zone指令，每个工作进程保持着自己的那份服务组配置拷贝，并且维护自己的相关的计数器集合。计数器涵盖组内每个服务的当前连接数，和向一个服务传递请求的失败尝试数。作为结果，服务组配置不能被动态修改。

当zone指令在upstream块中被包含，上游服务组配置被保存在一个被所有工作进程所共享的内存空间。这个案例是可以动态配置的，因为这些工作进程访问相同的上游服务组配置并且使用相同的相关计数器

zone指定在上游组的健康检查和动态配置中是强制性使用的。然而其他上游组的特性也可以在使用这些指令的时候被利用。

例如，如果一个组的配置没有被共享，每个工作进程维护着自己的转发请求到服务的失败尝试次数的计数器（通过max_fails参数设置）。在这种情况下，每个请求仅到达一个工作进程。当这个被选中来处理请求的工作进程转发请求到服务失败的时候，其他工作进程对此一无所知。当一些工作进程认定一个服务不可用，其他服务可能仍然向这个服务发送请求。对于一个服务要被最终认定不可用，在通过fail_timeout参数设置的时间框架期间内的失败尝试次数必须等于max_fails乘以工作进程数。另一方面zone指令保证了预期的效果。

相似的，没有zone指令，最少连接数（Least Connections）负载均衡方法可能也不能像预期的那样工作，至少低负载情况下。这种方式将请求转发到带有最少活跃连接数的服务。如果组配置没有被共享，每个工作进程使用它自己的连接数计数器并且可能发送请求到另外一个工作进程刚刚发送过请求的相同服务。然而，你可以提高连接数来减少这个影响，在高负载情况下请求在工作进程之间被平均地分发，并且最少连接数方法（Least Connections）按预期工作。

###### 设置Zone大小

推荐一个理想的memory‑zone 的大小是不可能的，因为使用模式差异很大。需要的内存量由开启哪些特性（比如会话持久化，健康检查以及DNS re-resolving）以及这些上游服务被识别的方式来决定。

比如，开启sticky_route 会话持久方法和一个简单的健康检查，一个256KB的zone可以支持识别的上游服务数的信息：

- 128 servers (each defined as an IP‑address:port pair)

- 88 servers (each defined as hostname:port pair where the hostname resolves to a single IP address)

- 12 servers (each defined as hostname:port pair where the hostname resolves to multiple IP addresses)

  



##### a9、用DNS配置Http负载均衡

利用DNS，一个服务组配置可以在运行时被动态改变。

在server指令中，对于一个上游组中的被一个域名所识别的这些服务，Nginx Plus可以监控存在于相关DNS记录中的IP地址列表的变化。并且在不用重启的情况下自动地应用这些"变化"到上游组的负载均衡。这项功能可以通过以下动作完成：在http块中包含resolver指令，而且包含resolve 参数到server指令。

```
http {
    resolver 10.0.0.1 valid=300s ipv6=off;
    resolver_timeout 10s;
    server {
        location / {
            proxy_pass http://backend;
        }
    }
    upstream backend {
        zone backend 32k;
        least_conn;
        # ...
        server backend1.example.com resolve;
        server backend2.example.com resolve;
    }
}
```

在这个示例中，server指令中的resolve参数告诉Nginx Plus阶段性地将backend1.example.com和backend2.example.com这两个域名解析为IP地址。

这个resolver指令定义了Nginx Plus发送的请求所指向的DNS服务的IP地址。默认情况下，Nginx Plus按记录中的TTL(time-to-live)所指定的频率解析DNS记录，但是你可以通过valid参数重写TTL，在这个示例中，TTL是300s或者说5分钟。

可选项ipv6=off意味着只有IPv4地址被用于负载均衡，然而默认情况下，IPv4和IPv6的IP地址的解析都被支持。

如果一个域名解析为数个IP地址，这些IP地址被保存到上游配置并用于负载均衡。在我们的示例中，这些服务通过least_connection负载均衡方法被均衡负载。如果一个服务的IP地址列表发生修改，Nginx Plus立即在新的地址集合中开启负载均衡。

#### b、TCP and UDP Load Balancing  

//Todo

#### c、HTTP Health Checks

Nginx和Nginx Plus可以持续测试你的上游服务，防止服务失败，并且优雅地添加恢复的服务到负载均衡组中。

###### c1、Passive Health Checks

对于主动性的健康检查，Nginx和Nginx Plus监控发生的，和试图恢复失败连接的交易。如果这个交易仍然不能被恢复，Nginx和Nginx Plus标记这个服务为不可用，并且临时停止向它发送请求直到它再次被标记为活跃。

对于每个上游服务来说，一个上游服务被标记为不可用的条件可以用upstream块中的server指令的参数来定义。

- fail_timeout——为要被标记为不可用的服务设置一个时间，这个时间内会一些失败发生。同样设置了这个服务被标记为不可用的时间（区别于前半句的时间，这个时间表示不可用状态持续时间，默认10s）。
- max_fails——为要被标记为不可用的服务设置了一个在fail_timeout期间内发生的错误尝试次数（默认一次尝试）。

在下面这个例子中，如果Nginx向一个服务发送一个请求失败或者没有从这个服务收到一个响应3次在30秒内。Nginx将这个服务标记为不可用，不可用状态持续30s。

```
upstream backend {
    server backend1.example.com;
    server backend2.example.com max_fails=3 fail_timeout=30s;
}
```

注意：如果一个组中只有一个单一服务，slow_start，fail_timeout，max_fails参数都将被忽略并且这个服务永远不会被标记为不可用。

###### c2、Active Health Checks

Nginx Plus可以借助 向每个服务发送特殊的健康检查请求并且验证正确的响应 来检查上游服务的健康。

开启主动健康检查

- 在向上游组发送请求的location中，包含了health_check指令

  ```
  server {
      location / {
          proxy_pass http://backend;
          health_check;
      }
  }
  ```

  这个片段定了了一个向一个叫backend的上游组发送所有请求（location /）的服务。它也用health_check指令开启了先进的健康监控。默认情况下，每隔五秒Nginx Plus向backend组内的每个服务发送一个"/"请求。如果任何交流错误或者超时发生（服务用一个不再200~399范围的状态码来响应）健康检查失败。服务被标记为不健康。Nginx不会向它发送一个客户端请求直到它再次通过一次健康检查。

  按需要你可以指定另外一个端口用于健康检查，例如，对于在同一个主机上的服务的健康监控。用health_check指令的port参数指定一个新的端口。

  ```
  server {
      location / {
          proxy_pass   http://backend;
          health_check port=8080;
      }
  }
  ```

- 在上游服务组，用zone指令定义一个共享内存区域。

  ```
  http {
      upstream backend {
          zone backend 64k;
          server backend1.example.com;
          server backend2.example.com;
          server backend3.example.com;
          server backend4.example.com;
      }
  }
  ```

  这个zone被所有worker进程共享并且保存着对应上游组的配置。这开启了worker进程利用相同的计数器集合以记录来自组内服务的响应。

  用health_check指令的参数可以对主动健康检查的默认项进行重写。

  ```
  location / {
      proxy_pass http://backend;
      health_check interval=10 fails=3 passes=2;
  }
  ```

  这里，interval参数将健康检查之间的延迟从默认的5秒增加到了10s。要被标记为不健康fails参数要求服务失败三次健康检查（高于默认的1次），要被再次标记为健康pass参数意味着服务必须通过两次连续的检查 而不是默认的一次。

###### c3、指定请求的URI

​	在健康检查中用health_check指定的uri参数来设置请求的URI。

```
location / {
    proxy_pass http://backend;
    health_check uri=/some/path;
}
```

这个指定的uri被追加到为upstream块中的server所设置的服务域名或者IP地址后面。对于上面声明的样品backend组中的第一个服务来说，一个健康检查请求这个URI:**http://backend1.example.com/some/path**。

#### d、TCP Health Checks

//Todo

#### e、UDP Health Checks

//Todo

#### f、gRPC Health Checks

//Todo

#### g、Dynamic Configuration of Upstreams with the NGINX Plus API

//Todo

#### h、Accepting the PROXY Protocol

//Todo

### 3、Content Cache

这个部分描述了如何开启和配置来自被代理服务的响应缓存。

当缓存开启，Nginx Plus保存响应到一个磁盘缓存并且使用它们来保存客户端而不用每次必须代理相同内容的请求。

###### Enabling the Caching of Responses（开启响应缓存）

要开启缓存，在顶层http{}上下文中包含proxy_cache_path指令。这个强制性的首个参数是缓存内容的本地文件系统路径。这个强制性的keys_zone参数定义了用于存储缓存项元数据的共享内存区域的名称和大小。

```
http {
    ...
    proxy_cache_path /data/nginx/cache keys_zone=one:10m;
}
```

然后在你想缓存服务响应的上下文（protocol type，virtual server or location）中包含proxy_cache指令，同时指定proxy_cache_path指定的keys_zone参数所定义的区域名称。

```
http {
    ...
    proxy_cache_path /data/nginx/cache keys_zone=one:10m;
    server {
        proxy_cache mycache;
        location / {
            proxy_pass http://localhost:8000;
        }
    }
}
```

注意由keys_zone参数所定义的大小，并不能限制缓存响应数据的总量。缓存响应自身利用元数据的拷贝来存储到文件系统的指定文件中。为了限制缓存响应数据的量，将max_size参数包含到proxy_cached_path指令。（但是注意缓存数据的量可以临时超出这个限制，正如下面部分所描述）

###### NGINX Processes Involved in Caching（和缓存相关的nginx进程）

这有两个额外的和缓存相关的nginx进程

-  cache manager定期被激活来检查缓存状态。如果缓存大小超出了proxy_cathe_path指令中max_size参数所设置的限制，cache         将移除最近访问的数据。正如前面提到的，在cache manager激活之间的这段时间，一定量的缓存数据可能临时地超出限制。
- 在Nginx启动之后，cache loader只运行一次。它加载之前缓存过的数据相关的元数据到共享内存区域。加载一次全部的缓存可能消耗足量的资源以至于在启动后的几分钟减慢性能。为了避免这种情况，通过包含以下proxy_cache_path指令的参数来配置迭代（重复）缓存加载。
  1. `loader_threshold` – Duration of an iteration, in milliseconds (by default, `200`)
  2. `loader_files` – Maximum number of items loaded during one iteration (by default, `100`)
  3. `loader_sleeps` – Delay between iterations, in milliseconds (by default, `50`)

在下面的示例当中，迭代持续300毫秒或者直到200个项被加载

```
proxy_cache_path /data/nginx/cache keys_zone=one:10m loader_threshold=300 loader_files=200;
```

###### Specifying Which Requests to Cache（指定哪个请求被缓存）

默认情况下，在第一次接收到来自被代理服务响应的时候，Nginx Plus 缓存所有由Http GET和HEAD方法构成的请求的响应。Nginx Plus用请求字符串作为一个请求的key（identifier）。如果一个请求有相同的key对应着一个缓存响应，Nginx Plus发送被缓存的响应到客户端。你可以在http{}，server{}，或者location{}上下文来控制哪个响应被缓存。

要改变用于计算key请求特性，就把proxy_cache_key指令包含进去。

```
proxy_cache_key "$host$request_uri$cookie_user";
```

要定义一个带有相同key的请求最小的发生次数，在响应被缓存之前，包含proxy_cache_min_uses指令。

```
proxy_cache_min_uses 5;
```

要缓存不是GET和HEAD请求的响应，将它们和GET,HEAD一起作为参数列到proxy_cache_methods指令当中。

```
proxy_cache_methods GET HEAD POST;
```

###### Limiting or Disabling Caching（限制或禁止缓存）

more情况下，响应无限期地保存在在缓存中。它们只有在缓存超出了最大的设置大小的时候被移除，然后按照自从它们上次被请求的时间长短来排序。你可以通过包含在http{}，server{}，或者location{}上下文的指令来设置缓存响应被视为有效的时间长短，甚至设置它们有没有被使用过。

要限制带有指定状态码的缓存的响应被视为有效的时间的长短，包含proxy_cache_valid指令。

```
proxy_cache_valid 200 302 10m;
proxy_cache_valid 404      1m;
```

在这个示例中，带有200或者302状态码的响应有效时间是10分钟，带有404状态码的响应有效时间是1分钟。要定义带有所有状态码的响应的有效时间，指定any作为第一个参数

```
proxy_cache_valid any 5m;
```

要定义Nginx Plus不向客户端发送缓存的响应的条件，那么包含proxy_cache_bypass指令。每个参数定义了一个条件并且由一个变量组成。如果至少一个参数不为空并且不等于0，Nginx Plus不会查找缓存中的响应，而是直接把请求立即发向后端的服务。

```
proxy_cache_bypass $cookie_nocache $arg_nocache$arg_comment;
```

要定义Nginx Plus压根不缓存一个响应的条件，包含proxy_no_cache指令，用和proxy_cache_bypass指令相同的方法定义参数。

```
proxy_no_cache $http_pragma $http_authorization;
```

###### Purging Content From The Cache

//Todo

### 4、Web Server

### 5、Security Controls

### 6、Monitoring

### 7、Nginx 正向代理

​		正向代理类似一个出口网关，所有到达nginx的出口请求被nginx转发到被代理服务，nginx在收到被代理服务的响应后，将被代理服务的响应返回给客户端。

​		nginx配置如下：

```
http {
	#设置域名解析服务器
	resolver 223.5.5.5 valid=300s ipv6=off;
    resolver_timeout 10s;
	#设置正向代理server
    server{
        listen       8000;
        server_name  forward-proxy-server;

        location / {
            proxy_pass http://$http_host$request_uri;#$http_host——nginx变量，表示请求目标url；$request_uri——nginx变量，表示请求目标URI
             proxy_buffers 256 4k;
             proxy_max_temp_file_size 0k;
             proxy_connect_timeout 30;
             proxy_send_timeout 60;
             proxy_read_timeout 60;
        }

    }
}

```

​		RestTemplate正向代理设置所对应java代码如下：

```
		//初始化http实体
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<Object> httpEntity = new HttpEntity<>(new HashMap(), headers);

        //初始化代理(指定代理服务器的IP和端口号)
        Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("47.103.199.109", 8000));

        //初始化客户端http请求工厂
        SimpleClientHttpRequestFactory httpRequestFactory = new SimpleClientHttpRequestFactory();
        httpRequestFactory.setReadTimeout(10000);
        httpRequestFactory.setConnectTimeout(10000);
        httpRequestFactory.setProxy(proxy);

        //初始化RestTemplate
        RestTemplate restTemplate = new RestTemplate(httpRequestFactory);

        ResponseEntity<String> responseEntity = restTemplate.exchange("http://47.103.199.109:8811/host", HttpMethod.GET, httpEntity, String.class);
        System.out.println(responseEntity.getBody());
```

​		

