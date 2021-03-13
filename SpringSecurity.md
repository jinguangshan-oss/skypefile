# SpringSecurity

Spring Security 是一个提供认证，授权，和对常见攻击进行防护的一个框架。它是在保护基于spring应用程序方面的一个事实上的标准。

## 1、特性

### 1.1、Authentication（认证）

Spring Security为认证提供了综合支持，认证是我们验证 访问一个特定资源的某个人 身份的方式。一个来认证用户的通常方式是要求用户来输入用户名和密码。一旦认证被执行，我们就知道这个身份，并且可以执行authorization（授权）。

#### a、认证支持

Spring Security提供了内置的认证用户的支持。

#### b、密码存储

Spring Security的PasswordEncoder接口被用来执行一个单向的密码转换的方式以容许密码被安全地存储。给定的PasswordEncoder是一种转换方式，当密码转换需要两种方式，这种场景没有被设计。通常PasswordEncoder被用来存储一个密码，这个密码需要在认证时和一个用户提供的密码进行比较。

##### DelegatingPasswordEncoder（授权式密码加密器）

###### DelegatingPasswordEncoder介绍

在Spring Security 5.0之前，默认的PasswordEncoder是需要纯文本密码的NoOpPasswordEncoder，基于密码历史部分你可能猜测默认的PasswordEncoder当前是类似BCryptPasswordEncoder一样的东西。然而这忽略了3个现实问题：

- 有很多使用旧密码加密且不容易迁移的应用。
- 密码存储的最佳实践未来会再次改变
- 最为一款框架Spring Security不能频繁地做出较大改变

尽管如此，Spring Security引进了可以解决以下问题的DelegatingPasswordEncoder：

- 确保使用当前密码存储推荐对密码进行加密
- 允许以当代和传统的方式验证密码
- 允许在未来升级加密

你可以使用`PasswordEncoderFactories`很容易地构建一个DelegatingPasswordEncoder实例

```
PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
```

或者，你可以创建你自己的自定义实例，例如：

```
String idForEncode = "bcrypt";
Map encoders = new HashMap<>();
encoders.put(idForEncode, new BCryptPasswordEncoder());
encoders.put("noop", NoOpPasswordEncoder.getInstance());
encoders.put("pbkdf2", new Pbkdf2PasswordEncoder());
encoders.put("scrypt", new SCryptPasswordEncoder());
encoders.put("sha256", new StandardPasswordEncoder());

PasswordEncoder passwordEncoder = new DelegatingPasswordEncoder(idForEncode, encoders);
```

###### Password Storage Format（密码存储格式）

```
{id}encodedPassword
```

这个id是一个用于查找哪个PasswordEncoder应当被使用的标识，并且encodedPassword是被选中的PasswordEncoder加密过的初始密码。id必须在密码的开头，以"{"开始，以"}"结束。如果id不能被找到，id将为null。例如，下列是用不同id加密的密码列表。

```
#When matching it would delegate to BCryptPasswordEncoder
{bcrypt}$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG 

#When matching it would delegate to NoOpPasswordEncoder
{noop}password 

#When matching it would delegate to Pbkdf2PasswordEncoder
{pbkdf2}5d923b44a6d129f3ddf3e3c8d29412723dcbde72445e8ef6bf3b508fbf17fa4ed4d6b99ca763d8dc 

#When matching it would delegate to SCryptPasswordEncoder
{scrypt}$e0801$8bWJaSu2IKSn9Z9kM+TPXfOc/9bdYSrN1oD9qfVThWEwdRTnO7re7Ei+fUZRJ68k9lTyuTeUp4of4g24hHnazw==$OAOec05+bXxvuu/1qZ6NUR+xQYvYv7BeL1QxwRpY5Pc=  

#When matching it would delegate to StandardPasswordEncoder
{sha256}97cde38028ad898ebc02e690819fa220e88c62e0699403e94fff291cfffaf8410849f27605abcbc0 .
```

一些用户可能担心存储格式是为潜在的黑客提供的。不用担心因为密码存储并不依赖于算法的私密性。此外，大多格式对于一个黑客来说在没有前缀的情况下很容易算出。比如BCrypt 密码一般以`$2a$`开头。

###### Password Encoding（密码加密）

被传入构造器的`idForEncode`决定了哪个 `PasswordEncoder` 将被用来加密密码。在我们上面构建的`DelegatingPasswordEncoder`里，那意味着加密密码的结果将被委托给 `BCryptPasswordEncoder`并且以`{bcrypt}`作为前缀。最终结果将看起来像：

```
{bcrypt}$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG
```

###### Password Matching（密码匹配）

匹配是基于{id}和id到构造器中提供的`PasswordEncoder`的映射来完成的。我们的密码存储格式的示例提供了一个这个是如何完成的可用的示例。默认情况下，用一个password和一个没有映射的id (including a null id) 来调用`matches(CharSequence, String)`方法的结果将导致一个`IllegalArgumentException`。这个行为可以自定义通过使用：`DelegatingPasswordEncoder.setDefaultPasswordEncoderForMatches(PasswordEncoder)`.

通过使用id我们可以匹配上任意密码加密，而不是是用先进的密码加密手段加密密码。这非常重要，因为与加密技术不同，密码的hash散列被设计成没有简单的方法来恢复明文。既然没有方法恢复明文，这就使得迁移密码变得困难。然而对于用户来讲迁移`NoOpPasswordEncoder`就很简单，我们选择默认把它包含进去以使得开始入门体验更简单。

###### Getting Started Experience（入门体验）

如果你在做一个demo或者sample，花时间计算你的用户的密码的hash散列是有点麻烦的。这里有使这变得简单的方便的机制，但是这还没有计划投入生产。

```
User user = User.withDefaultPasswordEncoder()
  .username("user")
  .password("password")
  .roles("user")
  .build();
System.out.println(user.getPassword());
// {bcrypt}$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG
```

如果你在创建多个用户，你也可以重复使用这个builder

```
UserBuilder users = User.withDefaultPasswordEncoder();
User user = users
  .username("user")
  .password("password")
  .roles("USER")
  .build();
User admin = users
  .username("admin")
  .password("password")
  .roles("USER","ADMIN")
  .build();
```

This does hash the password that is stored, but the passwords are still exposed in memory and in the compiled source code. Therefore, it is still not considered secure for a production environment. For production, you should [hash your passwords externally](https://docs.spring.io/spring-security/site/docs/5.4.5/reference/html5/#authentication-password-storage-boot-cli).

这确认计算了存储的密码的散列，但是这些密码仍然暴露在内存和编译过的源代码中。然而，对于一个生产环境来说这仍然不能被视为是安全的。对于生产，你应该在外部计算你的密码的散列。

###### Encode with Spring Boot CLI（用spring boot cli加密）

加密你的密码的最容易方法[Spring Boot CLI](https://docs.spring.io/spring-boot/docs/current/reference/html/spring-boot-cli.html)

例如，下面将使用DelegatingPasswordEncoder来加密密码：

```
spring encodepassword password
{bcrypt}$2a$10$X5wFBtLrL/kHcmrOGGTrGufsBX8CJ0WpQpF3pgeuxBB/H73BK1DW6

```

###### Troubleshooting（疑难解答）

当存储密码中的其中一个没有像[Password Storage Format](https://docs.spring.io/spring-security/site/docs/5.4.5/reference/html5/#authentication-password-storage-dpe-format)所描述的那样有id时，下列的错误将发生。

```
java.lang.IllegalArgumentException: There is no PasswordEncoder mapped for the id "null"
    at org.springframework.security.crypto.password.DelegatingPasswordEncoder$UnmappedIdPasswordEncoder.matches(DelegatingPasswordEncoder.java:233)
    at org.springframework.security.crypto.password.DelegatingPasswordEncoder.matches(DelegatingPasswordEncoder.java:196)
```

解决错误的最容易的方法是转而明确地指定你的密码加密所用的`PasswordEncoder` 。解决它最容易的方法是指明你的密码目前是如何被存储并且明确地提供正确的`PasswordEncoder`

如果你在从Spring Security 4.2.x 迁移，你可以返回到先前使用[exposing a `NoOpPasswordEncoder` bean](https://docs.spring.io/spring-security/site/docs/5.4.5/reference/html5/#authentication-password-storage-configuration)的行为。

或者，你可以用正确的id第你所有的密码加上前缀并且继续使用`DelegatingPasswordEncoder`。例如你正在使用BCrypt，你将从下面这些东西中迁移你的密码：

```
$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG
```

to

```
{bcrypt}$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG
```

For a complete listing of the mappings refer to the Javadoc on [PasswordEncoderFactories](https://docs.spring.io/spring-security/site/docs/5.0.x/api/org/springframework/security/crypto/factory/PasswordEncoderFactories.html).

对于一个完整的映射集合，参考 [PasswordEncoderFactories](https://docs.spring.io/spring-security/site/docs/5.0.x/api/org/springframework/security/crypto/factory/PasswordEncoderFactories.html)上面的Javadoc。

### 1.2、Protection Against Exploits（漏洞防护）



## 2、Servlet Security

### 2.1、过滤器回顾

Spring Security 的Servlet支持是基于Servlet 的 Filter,下图展示了单个的HttpRequest对应处理器的典型分层。

![filterchain](https://docs.spring.io/spring-security/site/docs/5.4.5/reference/html5/images/servlet/architecture/filterchain.png)

Client发送一个请求到应用，然后container创建一个包含了Servlet和Filter的FilterChain，FilterChain基于请求URI的Path处理HttpServletRequest。在SpringMVC应用当中，这个Servlet是一个DispatcherServlet实例。然而，多个Filter可以用于：

- 防止下游Filter和Servlet被调用，在这种情况下，Filter通常会编写HttpServletResponse。
- 修改下游Filter和Servlet所使用的HttpServletRequest或者HttpServletResponse

### 2.2、DelegatingFilterProxy（委托式Filter代理）

Spring提供了一个名为DelegatingFilterProxy的Filter的实现，它允许在Servlet容器的生命周期和Spring的ApplicationContext之间建立桥梁（桥接关系）。Servlet容器允许用它自己的标注册Filter。但是它不知道Spring定义的Bean。DelegatingFilterProxy可以通过标准的Servlet容器机制被注册，却把所有工作委派给实现了Filter的Spring Bean。下图展示了DelegatingFilterProxy是如何适配Filter和FilterChain的。

![delegatingfilterproxy](https://docs.spring.io/spring-security/site/docs/5.4.5/reference/html5/images/servlet/architecture/delegatingfilterproxy.png)

DelegatingFilterProxy从ApplicationContext上寻找Bean Filter，然后调用它。DelegatingFilterProxy的伪代码如下所示：

```
public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) {
    // Lazily get Filter that was registered as a Spring Bean
    // For the example in DelegatingFilterProxy delegate is an instance of Bean Filter0
    Filter delegate = getFilterBean(someBeanName);
    // delegate work to the Spring Bean
    delegate.doFilter(request, response);
}
```



### 2.3、FilterChainProxy

Spring Sercurity 的Servlet支持包含在FilterChainProxy里面，FilterChainProxy是一个Spring Sercurity提供的特殊的Filter，它允许通过SercurityFilterChain委托【任务】到很多Filter。既然FilterChainProxy是一个Bean，那么他通常被包含在DelegatingFilterProxy。

![filterchainproxy](https://docs.spring.io/spring-security/site/docs/5.4.5/reference/html5/images/servlet/architecture/filterchainproxy.png)



### 2.4、SecurityFilterChain

SecurityFilterChain被FilterChainProxy使用，用来决定哪个Sercurity Filter应当被调用。

![securityfilterchain](https://docs.spring.io/spring-security/site/docs/5.4.5/reference/html5/images/servlet/architecture/securityfilterchain.png)

SecurityFilterChain中的Sercurity Filter通常是Bean，但是他们注册在FilterChainProxy上而不是注册在DelegatingFilterProxy。FilterChainProxy提供了很多优势相较于直接注册到Servlet 容器和DelegatingFilterProxy来说。

首先，它提供了所有Spring Security的Servlet支持的起点。因此你可以在FilterChainProxy上添加一个调试断点来对Spring Security的Servlet支持排除故障，这是一个很好的起点位置。

其次，由于FilterChainProxy是Spring Security安全使用的核心，它可以执行非可选的任务。例如它清理SecurityContext以避免内存泄漏。它还应用Spring Security的HttpFirewall来保护应用免受某些类型的攻击。

事实上，FilterChainProxy可以用作决定哪个SecurityFilterChain被使用。这允许为应用程序的不同部分提供完全独立的配置。

![multi securityfilterchain](https://docs.spring.io/spring-security/site/docs/5.4.5/reference/html5/images/servlet/architecture/multi-securityfilterchain.png)

在多SecurityFilterChain配置中，FilterChainProxy决定了哪个被使用。只有第一个匹配的SecurityFilterChain会被调用。如果这样/api/messages/一个URL被请求，它首先会匹配到SecurityFilterChain0，所以只有SecurityFilterChain0被调用即使SecurityFilterChainn也满足匹配。如果这样/messages/的URL被请求，它将不会匹配到SecurityFilterChain0，所以FilterChainProxy将继续尝试每一个SecurityFilterChain，假设没有其他满足匹配的SecurityFilterChain，那么SecurityFilterChainn将会被调用。

注意SecurityFilterChain0有三个Filter实例配置，SecurityFilterChainn有四个Filter实例配置。需要注意到SecurityFilterChain都是唯一的，并且可以单独配置。事实上当应用想要Spring Secutity忽略某些请求的时候，SecurityFilterChain可以有0个Filter。

### 2.5、Security Filters

Security Filters 通过SecurityFilterChain API插入FilterChainProxy，Filter顺序很重要，通常不需要知道Filter的顺序，然而，有时候知道Filter的顺序是有益的。下面是Spring Security Filter 排序的完整集合

- ChannelProcessingFilter
- WebAsyncManagerIntegrationFilter
- SecurityContextPersistenceFilter
- HeaderWriterFilter
- CorsFilter
- CsrfFilter
- LogoutFilter
- OAuth2AuthorizationRequestRedirectFilter
- Saml2WebSsoAuthenticationRequestFilter
- X509AuthenticationFilter
- AbstractPreAuthenticatedProcessingFilter
- CasAuthenticationFilter
- OAuth2LoginAuthenticationFilter
- Saml2WebSsoAuthenticationFilter
- [`UsernamePasswordAuthenticationFilter`](https://docs.spring.io/spring-security/site/docs/5.4.5/reference/html5/#servlet-authentication-usernamepasswordauthenticationfilter)
- OpenIDAuthenticationFilter
- DefaultLoginPageGeneratingFilter
- DefaultLogoutPageGeneratingFilter
- ConcurrentSessionFilter
- [`DigestAuthenticationFilter`](https://docs.spring.io/spring-security/site/docs/5.4.5/reference/html5/#servlet-authentication-digest)
- BearerTokenAuthenticationFilter
- [`BasicAuthenticationFilter`](https://docs.spring.io/spring-security/site/docs/5.4.5/reference/html5/#servlet-authentication-basic)
- RequestCacheAwareFilter
- SecurityContextHolderAwareRequestFilter
- JaasApiIntegrationFilter
- RememberMeAuthenticationFilter
- AnonymousAuthenticationFilter
- OAuth2AuthorizationCodeGrantFilter
- SessionManagementFilter
- [`ExceptionTranslationFilter`](https://docs.spring.io/spring-security/site/docs/5.4.5/reference/html5/#servlet-exceptiontranslationfilter)
- [`FilterSecurityInterceptor`](https://docs.spring.io/spring-security/site/docs/5.4.5/reference/html5/#servlet-authorization-filtersecurityinterceptor)
- SwitchUserFilter

### 2.6、Handling Security Exceptions

ExceptionTranslationFilter将AccessDeniedException和AuthenticationException转化为HttpResponse。ExceptionTranslationFilter作为其中一个Filter插入到FilterChainProxy中。

![exceptiontranslationfilter](https://docs.spring.io/spring-security/site/docs/5.4.5/reference/html5/images/servlet/architecture/exceptiontranslationfilter.png)

- 首先，ExceptionTranslationFilter调用FilterChain.doFilter(request, response)来调用应用程序的剩余部分

- 如果用户没有认证或者，出现AuthenticationException，那么开始认证

  SercurityContextHolder清理

  HttpServletRequest保存在RequestCache，当用户成功认证，RequestCache被用来重新发送原始请求

   被用来从客户端请求证书，例如它可能重定向到一个登陆页或者发送一个WWW-Authenticate Header

- 否则出现AccessDeniedException，请求被拒绝。AccessDeniedHandler被调用来处理异常。

ps：如果应用程序没有抛出AuthenticationException或者AccessDeniedException，那么ExceptionTranslationFilter将什么也不做。

ExceptionTranslationFilter的伪代码如下：

```
try {
    filterChain.doFilter(request, response); 
} catch (AccessDeniedException | AuthenticationException ex) {
    if (!authenticated || ex instanceof AuthenticationException) {
        startAuthentication(); 
    } else {
        accessDenied(); 
    }
}
```





## 3、Authentication

#### 3.1、SecurityContextHolder

Spring Security身份验证模型的核心是securitycontexholder。它包含SecurityContext。



![securitycontextholder](https://docs.spring.io/spring-security/site/docs/5.4.5/reference/html5/images/servlet/authentication/architecture/securitycontextholder.png)

SecurityContexHolder是Spring Security存储被认证的用户的详细信息的地方。Spring Security不关心SecurityContexHolder的组成，SecurityContexHolder包含一个值，然后这个值被用作当前通过认证的用户。

表示一个通过认证的用户的最简单的方法是直接设置SecurityContexHolder。

```
SecurityContext context = SecurityContextHolder.createEmptyContext(); 
Authentication authentication =
    new TestingAuthenticationToken("username", "password", "ROLE_USER"); 
context.setAuthentication(authentication);

SecurityContextHolder.setContext(context); 
```

- 我们通过创建一个空的SecurityContext开始。重要的是创建一个新的SecurityContext实例，而不是使用securitycontexholder . getcontext (). setauthentication (authentication)来避免多个线程之间的竞争条件。
- 下一步我们创建一个新的Authentication对象，Spring Security并不关心在SecurityContext里面Authentication是什么类型的实现，这里我们使用TestingAuthenticationToken，因为它非常简单。一个更常用的产品方案是`UsernamePasswordAuthenticationToken(userDetails, password, authorities)`.
- 最终我们在SecurityContextHolder上设置SecurityContext，Spring Security 将使用这个信息来进行授权

如果你想获取被授权主体的信息，你可以这样做：访问SecurityContextHolder。

```
SecurityContext context = SecurityContextHolder.getContext();
Authentication authentication = context.getAuthentication();
String username = authentication.getName();
Object principal = authentication.getPrincipal();
Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
```

默认情况下，SecurityContextHolder使用ThreadLocal来存储这些详细信息，这意味着SecurityContext始终对同一线程中的方法可用，即使SecurityContext没有显式地作为参数传递给这些方法。这种方法非常地安全，前提是在当前主题的请求被处理之后要小心地去清理线程。Spring Security的FilterChainProxy保证了SecurityContext总是被清理。	有些应用程序并不完全适合使用ThreadLocal，这是因为它们处理线程的特定方式。例如，Swing客户机可能希望Java虚拟机中的所有线程都使用相同的安全上下文。

SecurityContextHolder可以在启动时配置一个策略，以指定您希望上下文如何存储。对于独立的应用程序，您将使用securitycontexholder.MODE_GLOBAL策略。其他应用程序可能希望由安全线程生成的线程也具有相同的安全身份，通过使用SecurityContextHolder.MODE_INHERITABLETHREADLOCAL可以达到这个目的。你可以用两种方法来改变默认的SecurityContextHolder.MODE_THREADLOCAL，第一个是设置系统属性，第二个是调用SecurityContextHolder上的静态方法。大多数应用程序不需要更改默认值，但如果需要更改，请查看SecurityContextHolder的JavaDoc以了解更多信息。

#### 3.2、SecurityContext

SecurityContext从SecurityContextHolder上获取，SecurityContext包含了一个Authentication对象

#### 3.3、Authentication

在Spring Security中，Authentication服务于两个目的。

- 作为AuthenticationManager的输入，提供用户的凭证以进行认证。在此场景中使用时，isAuthenticated()返回false。
- 代表当前被认证的用户，当前的Authentication可以从SecurityContext从获取。

Authentication包含：

1. principal——识别用户。当使用用户名/密码进行身份验证时，这通常是UserDetails的一个实例。
2. credentials——通常一个密码。在许多情况下，这将在用户身份验证后清除，以确保它不会泄漏。
3. authorities——GrantedAuthoritys是该用户被授予的高级权限。一些例子是角色或范围。

#### 3.4、GrantedAuthority

GrantedAuthoritys可以通过authentication . getauthority()方法获取。此方法提供了一个GrantedAuthoritys对象集合。毫无疑问，GrantedAuthoritys是一个授予principal的权限。这些权限通常是“角色”，如ROLE_ADMINISTRATOR或ROLE_HR_SUPERVISOR。这些角色稍后被web授权、方法授权和域对象授权所配置。Spring Security的其他部分能够解释这些授权，并期望它们出现。当使用基于用户名密码的认证的时候，GrantedAuthoritys经常被UserDetailsService加载。



一般情况下GrantedAuthority对象都是应用程序范围的权限。他们不是特定于给定域的对象。因此，您不太可能拥有一个被授予的权限来表示对编号54的Employee对象的权限，因为如果有数千个这样的权限，您将很快耗尽内存(或者，至少会导致应用程序花费很长时间来验证用户)当然，Spring Security是专门设计来处理这种常见需求的，但是您应该使用项目的域对象安全功能来实现这个目的。

#### 3.5、AuthenticationManager

​	AuthenticationManager是定义Spring Security  Filters如何执行身份验证的API。然后，通过调用AuthenticationManager的控制器(即Spring Security的Filterss)在SecurityContextHolder上设置返回的Authentication。如果您没有集成Spring Security的过滤器，您可以直接设置SecurityContextHolder，而不需要使用AuthenticationManager。

虽然AuthenticationManager的实现可以是任何东西，但最常见的实现是ProviderManager。

#### 3.6、ProviderManager

ProviderManager是AuthenticationManager最常用的实现。ProviderManager是一系列AuthenticationProviders的代表。每个AuthenticationProvider都有机会指示身份验证应该是成功的、失败的，或者指示它不能做出决定，并允许下游的AuthenticationProvider做出决定。如果没有一个配置AuthenticationProviders可以进行认证，然后认证将以一个ProviderNotFoundException异常表示失败。这是一种特殊的AuthenticationException表明ProviderManager没有被配置以支持传递给它的身份验证类型。

![providermanager](https://docs.spring.io/spring-security/site/docs/5.4.5/reference/html5/images/servlet/authentication/architecture/providermanager.png)

实际上，每个AuthenticationProvider都知道如何执行特定类型的身份验证。例如，一个AuthenticationProvider可能能够验证用户名/密码，而另一个可能能够验证SAML断言。这允许每个AuthenticationProvider执行非常特定类型的身份验证，同时支持多种身份验证类型，并且只公开单个AuthenticationManager bean。

ProviderManager还允许配置一个可选的父AuthenticationManager，当AuthenticationProvider无法执行身份验证时，该父AuthenticationManager会被咨询。父类可以是任何类型的AuthenticationManager，但它通常是ProviderManager的一个实例。

![providermanager parent](https://docs.spring.io/spring-security/site/docs/5.4.5/reference/html5/images/servlet/authentication/architecture/providermanager-parent.png)

事实上，多个ProviderManager实例可能共享相同的父AuthenticationManager。这在多个SecurityFilterChain实例中比较常见，这些实例有一些共同的身份验证(共享的父AuthenticationManager)，但也有不同的身份验证机制(不同的ProviderManager实例)。

![providermanagers parent](https://docs.spring.io/spring-security/site/docs/5.4.5/reference/html5/images/servlet/authentication/architecture/providermanagers-parent.png)

默认情况下，ProviderManager将尝试从Authentication对象中清除任何敏感数据，这个Authentication对象由一个成功的授权请求返回。这可以防止诸如密码之类的信息在HttpSession中被保留的时间超过必要的时间。

在使用用户对象的缓存时，这可能会导致问题，例如，在无状态应用程序中提高性能。如果Authentication包含对缓存中的对象(例如UserDetails实例)的引用，并且删除了它的凭据，那么将不再可能根据缓存的值进行身份验证。如果您正在使用缓存，则需要考虑到这一点。一个明显的解决方案是首先复制对象，要么在缓存实现中做，要么在创建返回的Authentication对象的AuthenticationProvider中做。或者，您可以禁用ProviderManager上的eraseCredentialsAfterAuthentication属性。有关更多信息，请参阅Javadoc。

#### 3.7、AuthenticationProvider

多个authenticationprovider可以注入到ProviderManager中。每个AuthenticationProvider执行特定类型的身份验证。例如，DaoAuthenticationProvider支持基于用户名/密码的身份验证，而JwtAuthenticationProvider支持对JWT令牌进行身份验证。

#### 3.8、用AuthenticationEntryPoint请求凭证

AuthenticationEntryPoint用于发送从客户端请求凭据的HTTP响应

有时，客户端会主动包括用户名/密码等凭据来请求资源。在种情况下，Spring Security不需要提供从客户端请求凭据的HTTP响应，因为它们已经包含在其中了

在其他情况下，客户端会向它们没有授权访问的资源发出未经身份验证的请求。在本例中，AuthenticationEntryPoint的实现用于从客户机请求凭据。AuthenticationEntryPoint实现可以执行重定向到登录页面，使用WWW-Authenticate头进行响应，等等。

#### 3.9、AbstractAuthenticationProcessingFilter

AbstractAuthenticationProcessingFilter用作验证用户凭据的基本过滤器。在对凭据进行身份验证之前，Spring Security通常使用AuthenticationEntryPoint请求凭据。 接下来，AbstractAuthenticationProcessingFilter可以验证提交给它的任何身份验证请求。

![abstractauthenticationprocessingfilter](https://docs.spring.io/spring-security/site/docs/5.4.5/reference/html5/images/servlet/authentication/architecture/abstractauthenticationprocessingfilter.png)

1. 当用户提交他们的凭证时，AbstractAuthenticationProcessingFilter根据要被验证的HttpServletRequest创建一个Authentication。创建的Authentication类型取决于AbstractAuthenticationProcessingFilter的子类。例如，UsernamePasswordAuthenticationFilter根据HttpServletRequest中提交的用户名和密码创建一个UsernamePasswordAuthenticationToken。

2. 接下来，Authentication被传递到AuthenticationManager以进行身份验证。、

3. 如果认证失败，则失败

   SecurityContextHolder被清理

   RememberMeServices.loginFail被调用，如果remember me没有配置，这是一个无操作。

   AuthenticationFailureHandler被调用。

4. 如果认证成功，则成功

   SessionAuthenticationStrategy收到新登录的通知。

   Authentication被设置在SecurityContextHolder，稍后，SecurityContextPersistenceFilter将SecurityContext保存到HttpSession中。

   RememberMeServices.loginSuccess被调用。如果remember me没有配置，这是一个无操作。

   ApplicationEventPublisher发布一个InteractiveAuthenticationSuccessEvent。

   AuthenticationSuccessHandler被调用。

#### 3.10、 Username/Password Authentication

验证用户身份的最常见方法之一是验证用户名和密码。因此，Spring Security为使用用户名和密码进行身份验证提供了全面的支持。

**Reading the Username & Password（读取用户名密码）**

Spring Security为从HttpServletRequest中读取用户名和密码提供了以下内置机制:

- Form Login(表单登录)
- Basic Authentication（基础认证）
- Digest Authentication（摘要试身份认证）

Storage Mechanisms（存储机制）

**每种支持的读取用户名和密码的机制都可以利用任何支持的存储机制:**

- Simple Storage with In-Memory Authentication（用内存中的Authentication进行简单存储）
- Relational Databases with JDBC Authentication（带有JDBC Authentication的关系型数据库）
- Custom data stores with UserDetailsService（使用UserDetailsService自定义的数据存储）
- LDAP storage with LDAP Authentication（使用LDAP身份验证的LDAP存储）

##### 3.10.1、Form Login

Spring Security支持通过html表单提供用户名和密码。本节详细介绍基于表单的身份验证如何在Spring Security中工作。

让我们看看基于表单的登录如何在Spring Security中工作。首先，我们将看到如何将用户重定向到登录表单。

![loginurlauthenticationentrypoint](https://docs.spring.io/spring-security/site/docs/5.4.5/reference/html5/images/servlet/authentication/unpwd/loginurlauthenticationentrypoint.png)

该图建立在SecurityFilterChain图表的基础上。

1. 首先，用户向未授权的资源/私有发起未经身份验证的请求
2. Spring Security的FilterSecurityInterceptor表示,未经身份验证的请求被拒绝 通过抛出AccessDeniedException。
3. 由于用户没有经过身份验证，因此ExceptionTranslationFilter启动启动身份验证，并使用配置的AuthenticationEntryPoint发送重定向到登录页面。在大多数情况下，AuthenticationEntryPoint是LoginUrlAuthenticationEntryPoint的一个实例。
4. 然后，浏览器将请求它被重定向到的登录页面。
5. 在应用程序中，必须呈现登录页面。

提交用户名和密码时，UsernamePasswordAuthenticationFilter对用户名和密码进行身份验证。UsernamePasswordAuthenticationFilter扩展了AbstractAuthenticationProcessingFilter，因此这个图看起来应该非常接近。

![usernamepasswordauthenticationfilter](https://docs.spring.io/spring-security/site/docs/5.4.5/reference/html5/images/servlet/authentication/unpwd/usernamepasswordauthenticationfilter.png)



1. 当用户提交他们的用户名和密码时，UsernamePasswordAuthenticationFilter创建一个UsernamePasswordAuthenticationToken，这是一种通过从HttpServletRequest中提取用户名和密码的Authentication类型。

2. 接下来，将UsernamePasswordAuthenticationToken传递到AuthenticationManager中以进行身份验证。AuthenticationManager的详细信息取决于如何存储用户信息。

3. 如果身份验证失败，则失败。

   SecurityContextHolder被清理

   RememberMeServices.loginFail被调用，如果remember me没有配置，这是一个无操作。

   AuthenticationFailureHandler被调用。

4. 如果验证成功，则验证成功。

   SessionAuthenticationStrategy收到新登录的通知。

   Authentication被设置在SecurityContextHolder，稍后，SecurityContextPersistenceFilter将SecurityContext保存到HttpSession中。

   RememberMeServices.loginSuccess被调用。如果remember me没有配置，这是一个无操作。

   ApplicationEventPublisher发布一个InteractiveAuthenticationSuccessEvent。

   AuthenticationSuccessHandler被调用。

默认情况下，Spring Security表单登录是启用的。但是，只要提供了任何基于servlet的配置，就必须显式地提供基于表单的登录。一个最小的，显式的Java配置可以在下面找到:

```
protected void configure(HttpSecurity http) {
    http
        // ...
        .formLogin(withDefaults());
}
```

在这个配置中，Spring Security将呈现一个默认的登录页面。大多数生产应用程序都需要定制的登录表单。

下面的配置演示了如何提供自定义登录表单。

```
protected void configure(HttpSecurity http) throws Exception {
    http
        // ...
        .formLogin(form -> form
            .loginPage("/login")
            .permitAll()
        );
}
```

当在Spring安全配置中指定登录页面时，您负责呈现页面。下面是一个模板，产生一个HTML登录表单，符合登录/login页面:

```
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:th="https://www.thymeleaf.org">
    <head>
        <title>Please Log In</title>
    </head>
    <body>
        <h1>Please Log In</h1>
        <div th:if="${param.error}">
            Invalid username and password.</div>
        <div th:if="${param.logout}">
            You have been logged out.</div>
        <form th:action="@{/login}" method="post">
            <div>
            <input type="text" name="username" placeholder="Username"/>
            </div>
            <div>
            <input type="password" name="password" placeholder="Password"/>
            </div>
            <input type="submit" value="Log in" />
        </form>
    </body>
</html>
```

关于默认的HTML表单有几个关键点:

- 表单应该执行一个post到/login
- 表单将需要包含一个CSRF标记，该标记将自动包含在Thymeleaf中。
- 表单应该在名为username的参数中指定用户名
- 表单应该在名为password的参数中指定密码
- 如果发现HTTP参数错误，则表示用户未能提供有效的用户名/密码
- 如果发现HTTP参数logout，则表示用户已成功注销

许多用户只需要定制登录页面，但是，如果需要，上面的所有内容都可以通过额外的配置进行定制。如果您正在使用Spring MVC，您将需要一个将GET /login映射到我们创建的登录模板的控制器。LoginController的一个最小示例如下:

```
@Controller
class LoginController {
    @GetMapping("/login")
    String login() {
        return "login";
    }
}
```

##### 3.10.2、 Basic Authentication

本节详细介绍Spring Security如何为基于servlet的应用程序提供基本HTTP身份验证支持。

让我们看看HTTP基本Authentication如何在Spring Security中工作。首先，我们看到WWW-Authenticate头被发送回一个未经身份验证的客户端。

![basicauthenticationentrypoint](https://docs.spring.io/spring-security/site/docs/5.4.5/reference/html5/images/servlet/authentication/unpwd/basicauthenticationentrypoint.png)

该图建立在SecurityFilterChain图表的基础上。

1. 用户对未授权的资源/私有发起未经身份验证的请求。
2. Spring Security的FilterSecurityInterceptor指出，通过抛出AccessDeniedException来拒绝未经身份验证的请求。
3. 因为用户没有经过身份验证，因此ExceptionTranslationFilter会启动身份验证。配置的AuthenticationEntryPoint是发送WWW-Authenticate报头的BasicAuthenticationEntryPoint实例。RequestCache通常是一个NullRequestCache，它不保存请求，因为客户机能够重发它最初请求的请求。

当客户端接收到WWW-Authenticate标头时，它知道应该重试用户名和密码。下面是正在处理的用户名和密码的流程。

![basicauthenticationfilter](https://docs.spring.io/spring-security/site/docs/5.4.5/reference/html5/images/servlet/authentication/unpwd/basicauthenticationfilter.png)

该图建立在SecurityFilterChain图表的基础上。

1. 当用户提交用户名和密码时，BasicAuthenticationFilter创建一个UsernamePasswordAuthenticationToken，这是一种通过从HttpServletRequest中提取用户名和密码的身份验证类型。

2. 将UsernamePasswordAuthenticationToken传递到AuthenticationManager中以进行身份验证。AuthenticationManager的详细信息取决于如何存储用户信息。

3. 如果身份验证失败，那么就失败

   SecurityContextHolder被清除。

   RememberMeServices.loginFail被调用。如果remember me没有配置，这是一个无操作。

   调用AuthenticationEntryPoint来触发再次发送WWW-Authenticate。

4. 如果身份验证成功，则成功。

   在SecurityContextHolder上设置身份验证。

   RememberMeServices.loginSuccess被调用。如果remember me没有配置，这是一个无操作。

   BasicAuthenticationFilter调用FilterChain.doFilter(request,response)以继续应用程序逻辑的其余部分。

默认情况下，Spring Security的HTTP基本身份验证支持是启用的。但是，一旦提供了任何基于servlet的配置，就必须显式地提供HTTP Basic。

一个最小的显式配置可以在下面找到:

```
protected void configure(HttpSecurity http) {
    http
        // ...
        .httpBasic(withDefaults());
}
```

##### 3.10.3、Digest Authentication

##### 3.10.4、In-Memory Authentication

Spring Security的InMemoryUserDetailsManager实现了UserDetailsService，为在内存中检索的基于用户名/密码的身份验证提供支持。InMemoryUserDetailsManager通过实现UserDetailsManager接口来管理用户详情。当Spring Security被配置为接受用户名/密码进行身份验证时，将使用基于UserDetails的身份验证。

在这个示例中，我们使用Spring Boot CLI对password的密码进行编码，并获得编码后的密码{bcrypt}$2a$10$GRLdNijSQMUvl/ au9ofl . edwmoohzzs7 . rmnsjj . 0fxo /BTk76klW。

```
@Bean
public UserDetailsService users() {
    UserDetails user = User.builder()
        .username("user")
        .password("{bcrypt}$2a$10$GRLdNijSQMUvl/au9ofL.eDwmoohzzS7.rmNSJZ.0FxO/BTk76klW")
        .roles("USER")
        .build();
    UserDetails admin = User.builder()
        .username("admin")
        .password("{bcrypt}$2a$10$GRLdNijSQMUvl/au9ofL.eDwmoohzzS7.rmNSJZ.0FxO/BTk76klW")
        .roles("USER", "ADMIN")
        .build();
    return new InMemoryUserDetailsManager(user, admin);
}
```

上面的示例以安全格式存储密码，但是在入门体验方面还有很多需要改进的地方。

在下面的示例中，我们利用了User。使用defaultpasswordencoder，确保存储在内存中的密码受到保护。但是，它不能通过反编译源代码来防止获取密码。因此，用户。withDefaultPasswordEncoder应该只用于“入门”，而不是用于生产。

```
@Bean
public UserDetailsService users() {
    // The builder will ensure the passwords are encoded before saving in memory
    UserBuilder users = User.withDefaultPasswordEncoder();
    UserDetails user = users
        .username("user")
        .password("password")
        .roles("USER")
        .build();
    UserDetails admin = users
        .username("admin")
        .password("password")
        .roles("USER", "ADMIN")
        .build();
    return new InMemoryUserDetailsManager(user, admin);
}
```

没有简单的方法来使用User。基于XML配置的defaultpasswordencoder。对于演示或刚刚开始，您可以选择在密码前加上{noop}来表示不应该使用加密。

```
<user-service>
    <user name="user"
        password="{noop}password"
        authorities="ROLE_USER" />
    <user name="admin"
        password="{noop}password"
        authorities="ROLE_USER,ROLE_ADMIN" />
</user-service>
```



##### 3.10.5、JDBC Authentication

Spring Security的JdbcDaoImpl实现了UserDetailsService，为使用JDBC检索的基于用户名/密码的身份验证提供支持。JdbcUserDetailsManager扩展了JdbcDaoImpl，通过UserDetailsManager接口提供对UserDetails的管理。当Spring Security被配置为接受用户名/密码进行身份验证时，将使用基于UserDetails的身份验证。

下面我们将讨论:

- Spring Security JDBC Authentication使用的Default Schema
- 设置数据源
- JdbcUserDetailsManager Bean

###### Default Schema

Spring Security为基于JDBC的身份验证提供了默认查询。本节提供了使用默认查询的相应的默认模式。你将需要调整模式以匹配任何自定义查询以及你使用的数据方言。

###### User Schema

JdbcDaoImpl需要表来加载密码、帐户状态(启用或禁用)和用户的权限(角色)列表。所需的默认模式可以在下面找到。

默认模式也作为一个名为org/springframework/security/core/userdetails/jdbc/users.ddl的类路径资源公开。

 **Default User Schema**

```
create table users(
    username varchar_ignorecase(50) not null primary key,
    password varchar_ignorecase(500) not null,
    enabled boolean not null
);

create table authorities (
    username varchar_ignorecase(50) not null,
    authority varchar_ignorecase(50) not null,
    constraint fk_authorities_users foreign key(username) references users(username)
);
create unique index ix_auth_username on authorities (username,authority);
```

Oracle是一种很流行的数据库选择，但是需要一种稍微不同的模式。您可以在下面找到用户的默认Oracle模式。

**Default User Schema for Oracle Databases**

```
CREATE TABLE USERS (
    USERNAME NVARCHAR2(128) PRIMARY KEY,
    PASSWORD NVARCHAR2(128) NOT NULL,
    ENABLED CHAR(1) CHECK (ENABLED IN ('Y','N') ) NOT NULL
);


CREATE TABLE AUTHORITIES (
    USERNAME NVARCHAR2(128) NOT NULL,
    AUTHORITY NVARCHAR2(128) NOT NULL
);
ALTER TABLE AUTHORITIES ADD CONSTRAINT AUTHORITIES_UNIQUE UNIQUE (USERNAME, AUTHORITY);
ALTER TABLE AUTHORITIES ADD CONSTRAINT AUTHORITIES_FK1 FOREIGN KEY (USERNAME) REFERENCES USERS (USERNAME) ENABLE;
```

###### Group Schema

如果应用程序利用组，则需要提供groups模式。组的默认模式可以在下面找到。

```
create table groups (
    id bigint generated by default as identity(start with 0) primary key,
    group_name varchar_ignorecase(50) not null
);

create table group_authorities (
    group_id bigint not null,
    authority varchar(50) not null,
    constraint fk_group_authorities_group foreign key(group_id) references groups(id)
);

create table group_members (
    id bigint generated by default as identity(start with 0) primary key,
    username varchar(50) not null,
    group_id bigint not null,
    constraint fk_group_members_group foreign key(group_id) references groups(id)
);
```

###### Setting up a DataSource

在配置JdbcUserDetailsManager之前，我们必须创建一个数据源。在我们的示例中，我们将设置一个用默认用户模式初始化的嵌入式数据源。

```
@Bean
DataSource dataSource() {
    return new EmbeddedDatabaseBuilder()
        .setType(H2)
        .addScript("classpath:org/springframework/security/core/userdetails/jdbc/users.ddl")
        .build();
}
```

在生产环境中，您需要确保设置一个连接指向外部数据源。

###### JdbcUserDetailsManager Bean

在这个示例中，我们使用Spring Boot CLI对password的密码进行编码，并获得编码后的密码{bcrypt}$2a$10$GRLdNijSQMUvl/ au9ofl . edwmoohzzs7 . rmnsjj . 0fxo /BTk76klW。有关如何存储密码的详细信息，请参阅PasswordEncoder部分。

```
@Bean
UserDetailsManager users(DataSource dataSource) {
    UserDetails user = User.builder()
        .username("user")
        .password("{bcrypt}$2a$10$GRLdNijSQMUvl/au9ofL.eDwmoohzzS7.rmNSJZ.0FxO/BTk76klW")
        .roles("USER")
        .build();
    UserDetails admin = User.builder()
        .username("admin")
        .password("{bcrypt}$2a$10$GRLdNijSQMUvl/au9ofL.eDwmoohzzS7.rmNSJZ.0FxO/BTk76klW")
        .roles("USER", "ADMIN")
        .build();
    JdbcUserDetailsManager users = new JdbcUserDetailsManager(dataSource);
    users.createUser(user);
    users.createUser(admin);
}
```



##### 3.10.6、UserDetails

UserDetails由UserDetailsService返回。DaoAuthenticationProvider验证UserDetails，然后返回一个认证，该认证的主体是已配置的UserDetailsService返回的UserDetails。

##### 3.10.7、UserDetailsService

DaoAuthenticationProvider使用UserDetailsService来检索用户名、密码和其他属性，以便使用用户名和密码进行身份验证。Spring Security提供了UserDetailsService的内存和JDBC实现

您可以通过将自定义UserDetailsService作为bean进行暴露，来定义自定义认证。下面将自定义认证，假设CustomUserDetailsService实现了UserDetailsService:

仅在未填充AuthenticationManagerBuilder且未定义AuthenticationProviderBean时才使用。

```
@Bean
CustomUserDetailsService customUserDetailsService() {
    return new CustomUserDetailsService();
}
```

##### 3.10.8、PasswordEncoder

Spring Security的servlet通过集成PasswordEncoder来支持安全地存储密码。可以通过公开一个PasswordEncoder Bean来定制Spring Security使用的PasswordEncoder实现。

##### 3.10.9、DaoAuthenticationProvider

DaoAuthenticationProvider是一个AuthenticationProvider实现，它利用UserDetailsService和PasswordEncoder来验证用户名和密码。

让我们看一下在Spring Security中，DaoAuthenticationProvider是如何工作的。图中解释了读取用户名和密码时AuthenticationManager如何工作的细节。

![daoauthenticationprovider](https://docs.spring.io/spring-security/site/docs/5.4.5/reference/html5/images/servlet/authentication/unpwd/daoauthenticationprovider.png)

1. 读取用户名和密码的身份验证过滤器将UsernamePasswordAuthenticationToken传递给由ProviderManager实现的AuthenticationManager。
2. ProviderManager被配置为使用类型为DaoAuthenticationProvider的AuthenticationProvider。
3. DaoAuthenticationProvider从UserDetailsService查找UserDetails。
4. DaoAuthenticationProvider然后使用PasswordEncoder对上一步中返回的UserDetails验证密码。
5. 当身份验证成功时，返回的身份验证类型为UsernamePasswordAuthenticationToken，并具有一个主体，该主体是配置的UserDetailsService返回的UserDetails。最终，身份验证过滤器将在securitycontexholder上设置返回的UsernamePasswordAuthenticationToken。

##### 3.10.10、LDAP Authentication

组织经常使用LDAP作为用户信息的中央存储库和身份验证服务。它还可以用于存储应用程序用户的角色信息。

当Spring Security被配置为接受用户名/密码进行身份验证时，Spring Security将使用基于LDAP的身份验证。然而，尽管使用用户名/密码进行身份验证，但它没有使用UserDetailsService进行集成，因为在绑定身份验证中，LDAP服务器不返回密码，因此应用程序不能执行密码验证。

对于如何配置LDAP服务器，有许多不同的场景，因此Spring Security的LDAP提供者是完全可配置的。

它使用单独的策略接口进行身份验证和角色检索，并提供了默认实现，可以对其进行配置以处理各种各样的情况。

###### Prerequisites（先决条件）

在尝试将LDAP与Spring安全性结合使用之前，您应该熟悉LDAP。下面的链接很好地介绍了所涉及的概念，并提供了使用免费LDAP服务器OpenLDAP建立目录的指南:https://www.zytrax.com/books/ldap/。

熟悉用于从Java访问LDAP的JNDI api也可能有用。我们在LDAP提供程序中没有使用任何第三方LDAP库(Mozilla、JLDAP等)，但Spring LDAP得到了广泛的使用，因此，如果您计划添加自己的定制，对该项目有一些熟悉可能会有用。

在使用LDAP身份验证时，确保正确配置LDAP连接池非常重要。如果您不熟悉如何做到这一点，可以参考Java LDAP文档。

###### Setting up an Embedded LDAP Server（设置一个嵌入式LDAP服务）

您需要做的第一件事是确保您有一个LDAP服务器来指向您的配置。为了简单起见，通常最好从嵌入式LDAP服务器开始。Spring Security支持使用以下两种方式:

- 嵌入式UnboundID服务器
- 嵌入式ApacheDS服务器

在下面的示例中，我们将下列对象作为用户公开。ldif作为类路径资源来初始化嵌入的LDAP服务器，用户user和admin的密码都是password。

```
dn: ou=groups,dc=springframework,dc=org
objectclass: top
objectclass: organizationalUnit
ou: groups

dn: ou=people,dc=springframework,dc=org
objectclass: top
objectclass: organizationalUnit
ou: people

dn: uid=admin,ou=people,dc=springframework,dc=org
objectclass: top
objectclass: person
objectclass: organizationalPerson
objectclass: inetOrgPerson
cn: Rod Johnson
sn: Johnson
uid: admin
userPassword: password

dn: uid=user,ou=people,dc=springframework,dc=org
objectclass: top
objectclass: person
objectclass: organizationalPerson
objectclass: inetOrgPerson
cn: Dianne Emu
sn: Emu
uid: user
userPassword: password

dn: cn=user,ou=groups,dc=springframework,dc=org
objectclass: top
objectclass: groupOfNames
cn: user
uniqueMember: uid=admin,ou=people,dc=springframework,dc=org
uniqueMember: uid=user,ou=people,dc=springframework,dc=org

dn: cn=admin,ou=groups,dc=springframework,dc=org
objectclass: top
objectclass: groupOfNames
cn: admin
uniqueMember: uid=admin,ou=people,dc=springframework,dc=org
```

###### Embedded UnboundID Server（嵌入式UnboundID服务）

如果你想使用UnboundID，请指定以下依赖项:

```
<dependency>
    <groupId>com.unboundid</groupId>
    <artifactId>unboundid-ldapsdk</artifactId>
    <version>4.0.14</version>
    <scope>runtime</scope>
</dependency>
```

然后可以配置嵌入式LDAP服务器

```
@Bean
UnboundIdContainer ldapContainer() {
    return new UnboundIdContainer("dc=springframework,dc=org",
                "classpath:users.ldif");
}
```

###### Embedded ApacheDS Server

Spring Security使用ApacheDS 1.x不再保留。不幸的是,ApacheDS 2.x只发布了没有稳定版本的里程碑版本。一旦ApacheDS 2.x的稳定版本已备妥，我们会考虑更新。

如果你想使用Apache DS，那么指定以下依赖项:

```
<dependency>
    <groupId>org.apache.directory.server</groupId>
    <artifactId>apacheds-core</artifactId>
    <version>1.5.5</version>
    <scope>runtime</scope>
</dependency>
<dependency>
    <groupId>org.apache.directory.server</groupId>
    <artifactId>apacheds-server-jndi</artifactId>
    <version>1.5.5</version>
    <scope>runtime</scope>
</dependency>
```

然后可以配置嵌入式LDAP服务器

```
@Bean
ApacheDSContainer ldapContainer() {
    return new ApacheDSContainer("dc=springframework,dc=org",
                "classpath:users.ldif");
}
```

###### //TODO....



## 4、Authorization

//todo

## 5、Java Configuration

Spring 3.1中为Spring框架添加了对Java配置的通用支持。从Spring Security 3.2开始，就有了Spring Security Java配置支持，允许用户在不使用任何XML的情况下轻松配置Spring Security。

如果您熟悉安全名称空间配置，那么您应该会发现它与安全Java配置支持之间有很多相似之处。

PS:Spring Security提供了许多示例应用程序，这些应用程序演示了Spring Security Java配置的使用。

### 5.1、Hello Web Security Java Configuration

第一步是创建Spring Security Java配置。该配置创建了一个称为springSecurityFilterChain的Servlet过滤器，它负责应用程序中的所有安全(保护应用程序url、验证提交的用户名和密码、重定向到登录表单等)。你可以在下面找到最基本的Spring安全Java配置示例:

```
import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.context.annotation.*;
import org.springframework.security.config.annotation.authentication.builders.*;
import org.springframework.security.config.annotation.web.configuration.*;

@EnableWebSecurity
public class WebSecurityConfig {

    @Bean
    public UserDetailsService userDetailsService() {
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(User.withDefaultPasswordEncoder().username("user").password("password").roles("USER").build());
        return manager;
    }
}
```

这个配置真的没有多少，但它做了很多。你可以找到下面的特性总结:

- 要求对应用程序中的每个URL进行身份验证

- 为您生成一个登录表单

- 允许具有用户名user和密码Password的用户通过基于表单的身份验证进行身份验证

- 允许用户注销

- CSRF攻击预防

- 会话固定保护

- 安全头（Security Header）集成

  HTTP对安全请求严格的传输安全

  X-Content-Type-Options集成

  缓存控制(可以稍后由应用程序覆盖，以允许缓存静态资源)

  X-XSS-Protection集成

  X-Frame-Options集成，帮助防止点击劫持（Clickjacking）

- 与以下Servlet API方法集成

  HttpServletRequest#getRemoteUser()
  HttpServletRequest#getUserPrincipal()
  HttpServletRequest#isUserInRole(java.lang.String)
  HttpServletRequest#login(java.lang.String, java.lang.String)
  HttpServletRequest#logout()

#### 5.1.1、AbstractSecurityWebApplicationInitializer

下一步是向war注册springSecurityFilterChain。这可以在Servlet 3.0+环境中使用Spring的WebApplicationInitializer支持的Java配置中实现。毫不奇怪，Spring Security提供了一个基类AbstractSecurityWebApplicationInitializer，它将确保为您注册springSecurityFilterChain。我们使用AbstractSecurityWebApplicationInitializer的方式不同，这取决于我们是已经在使用Spring，还是Spring Security是应用程序中唯一的Spring组件。

#### 5.1.2、 AbstractSecurityWebApplicationInitializer without Existing Spring

如果你没有使用Spring或Spring MVC，你需要将WebSecurityConfig传递到超类中，以确保配置被获取。你可以在下面找到一个例子:

```
import org.springframework.security.web.context.*;

public class SecurityWebApplicationInitializer
    extends AbstractSecurityWebApplicationInitializer {

    public SecurityWebApplicationInitializer() {
        super(WebSecurityConfig.class);
    }
}
```

SecurityWebApplicationInitializer将做以下事情:

- 为应用程序中的每个URL自动注册springSecurityFilterChain过滤器
- 添加一个ContextLoaderListener来加载WebSecurityConfig。

#### 5.1.3、AbstractSecurityWebApplicationInitializer with Spring MVC

如果我们在应用程序的其他地方使用Spring，我们可能已经有一个WebApplicationInitializer来加载我们的Spring配置。如果我们使用前面的配置，我们将得到一个错误。相反，我们应该将Spring Security注册到现有的ApplicationContext中。例如，如果我们使用Spring MVC, SecurityWebApplicationInitializer就会像下面这样:

```
import org.springframework.security.web.context.*;

public class SecurityWebApplicationInitializer
    extends AbstractSecurityWebApplicationInitializer {

}
```

这只会为应用程序中的每个URL注册springSecurityFilterChain过滤器。之后，我们要确保WebSecurityConfig已经加载到现有的ApplicationInitializer中。例如，如果我们使用Spring MVC，它将被添加到getRootConfigClasses()中

```
public class MvcWebApplicationInitializer extends
        AbstractAnnotationConfigDispatcherServletInitializer {

    @Override
    protected Class<?>[] getRootConfigClasses() {
        return new Class[] { WebSecurityConfig.class };
    }

    // ... other overrides ...
}
```

### 5.2、HttpSecurity

到目前为止，我们的WebSecurityConfig只包含了关于如何验证用户身份的信息。Spring Security如何知道我们需要要求所有用户进行身份验证?Spring Security是如何知道我们想要支持基于表单的身份验证的?实际上，有一个名为WebSecurityConfigurerAdapter的配置类正在幕后被调用。它有一个名为configure的方法，默认实现如下:

```
protected void configure(HttpSecurity http) throws Exception {
    http
        .authorizeRequests(authorize -> authorize
            .anyRequest().authenticated()
        )
        .formLogin(withDefaults())
        .httpBasic(withDefaults());
}
```

上面的默认配置:

- 确保对我们的应用程序的任何请求都要求对用户进行身份验证
- 允许用户通过基于表单的登录进行身份验证
- 允许用户使用HTTP基本身份验证进行身份验证

您将注意到，此配置与XML名称空间配置非常相似:

```
<http>
    <intercept-url pattern="/**" access="authenticated"/>
    <form-login />
    <http-basic />
</http>
```

### 5.3、Multiple HttpSecurity

我们可以配置多个HttpSecurity实例，就像我们可以有多个<http>块一样。关键是要多次扩展WebSecurityConfigurerAdapter。例如，下面是一个以/api/开头的URL的不同配置示例。

```
@EnableWebSecurity
public class MultiHttpSecurityConfig {
	
	//配置正常认证
    @Bean                                                             
    public UserDetailsService userDetailsService() throws Exception {
        // ensure the passwords are encoded properly
        UserBuilder users = User.withDefaultPasswordEncoder();
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(users.username("user").password("password").roles("USER").build());
        manager.createUser(users.username("admin").password("password").roles("USER","ADMIN").build());
        return manager;
    }
	
	//创建一个包含@Order的WebSecurityConfigurerAdapter实例，以指定应该首先考虑哪个WebSecurityConfigurerAdapter。
    @Configuration
    @Order(1)                                                        
    public static class ApiWebSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {
        protected void configure(HttpSecurity http) throws Exception {
        	//http.antMatcher声明这个HttpSecurity将只适用于以/api/开头的url
            http
                .antMatcher("/api/**")                               
                .authorizeRequests(authorize -> authorize
                    .anyRequest().hasRole("ADMIN")
                )
                .httpBasic(withDefaults());
        }
    }
	
	//创建WebSecurityConfigurerAdapter的另一个实例。如果URL不是以/api/开头，将使用此配置。此配置在ApiWebSecurityConfigurationAdapter之后被考虑，因为有一个@Order值在1之后(没有@Order则默认为last，即最后一个)。
    @Configuration                                                   
    public static class FormLoginWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .authorizeRequests(authorize -> authorize
                    .anyRequest().authenticated()
                )
                .formLogin(withDefaults());
        }
    }
}
```

### 5.4、Custom DSLs

您可以在Spring Security中提供自己的定制DSLs。例如，你可能有这样的东西:

```
public class MyCustomDsl extends AbstractHttpConfigurer<MyCustomDsl, HttpSecurity> {
    private boolean flag;

    @Override
    public void init(H http) throws Exception {
        // any method that adds another configurer
        // must be done in the init method
        http.csrf().disable();
    }

    @Override
    public void configure(H http) throws Exception {
        ApplicationContext context = http.getSharedObject(ApplicationContext.class);

        // here we lookup from the ApplicationContext. You can also just create a new instance.
        MyFilter myFilter = context.getBean(MyFilter.class);
        myFilter.setFlag(flag);
        http.addFilterBefore(myFilter, UsernamePasswordAuthenticationFilter.class);
    }

    public MyCustomDsl flag(boolean value) {
        this.flag = value;
        return this;
    }

    public static MyCustomDsl customDsl() {
        return new MyCustomDsl();
    }
}
```

这实际上是HttpSecurity.authorizeRequests()等方法的实现方式。

定制的DSL然后可以这样使用:

```
@EnableWebSecurity
public class Config extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .apply(customDsl())
                .flag(true)
                .and()
            ...;
    }
}
```

代码被调用的顺序如下:

- Config的configure方法中的代码被调用
- MyCustomDsl的init方法中的代码被调用
- 调用MyCustomDsl的configure方法中的代码

如果你愿意，你可以让WebSecurityConfigurerAdapter通过使用SpringFactories默认添加MyCustomDsl。例如，您将在名为META-INF/spring.factories的类路径上创建一个资源。有以下内容:

```
org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer = sample.MyCustomDsl
```

希望禁用默认值的用户可以明确地这样做。

```
@EnableWebSecurity
public class Config extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .apply(customDsl()).disable()
            ...;
    }
}
```

### 5.5、 Post Processing Configured Objects

Spring Security的Java配置并没有公开它配置的每个对象的每个属性。这简化了大多数用户的配置。毕竟，如果每个属性都公开了，用户就可以使用标准的bean配置。

虽然有很好的理由不直接公开每个属性，但用户可能仍然需要更高级的配置选项。为了解决这个Spring安全性问题，引入了ObjectPostProcessor的概念，它可以用来修改或替换由Java配置创建的许多对象实例。例如，如果你想在FilterSecurityInterceptor上配置filterSecurityPublishAuthorizationSuccess属性，你可以使用以下方法:

```
@Override
protected void configure(HttpSecurity http) throws Exception {
    http
        .authorizeRequests(authorize -> authorize 
            .anyRequest().authenticated()
            .withObjectPostProcessor(new ObjectPostProcessor<FilterSecurityInterceptor>() {
                public <O extends FilterSecurityInterceptor> O postProcess(
                        O fsi) {
                    fsi.setPublishAuthorizationSuccess(true);
                    return fsi;
                }
            })
        );
}
```

