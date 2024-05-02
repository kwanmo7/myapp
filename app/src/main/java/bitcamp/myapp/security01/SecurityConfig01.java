package bitcamp.myapp.security01;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

//@Configuration
//@EnableWebSecurity
public class SecurityConfig01 {
  private static final Log log = LogFactory.getLog(SecurityConfig01.class);
  
  public SecurityConfig01(){
    log.debug("SecurityConfig 객체 생성");
  }

  // Spring Security를 처리할 필터 체인을 준비
//  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    // 필터 체인에 들어갈 필터 설정
    // 1) 어떤 요청에 대해 Security Filter를 적용할지 설정
    //  => 모든 요청에 대해 Security 인증 필터를 통과하도록 설정
    //     인증받지 않은 사용자는 모든 요청을 거부
    // 2) 어떤 http 요청에 대해 security filter를 적용할지 설정
    //  => Spring Security 기본 설정을 그대로 사용
    // 3) 로그인폼을 지정
    //  => Spring Security가 만들어주는 로그인 폼을 그대로 사용
    http
        .authorizeHttpRequests((authorize) -> authorize
            .anyRequest().authenticated() // 어떤 요청에 대해서 적용할지 설정
        )
        .httpBasic(Customizer.withDefaults())  // http 요청
        .formLogin(Customizer.withDefaults()); // 로그인 폼

    // HttpSecurity 객체에 설정한대로 동작할 수 있는 필터를 구성
    return http.build();
  }

  // 사용자 정보를 리턴해주는 객체
//  @Bean
  public UserDetailsService userDetailsService() {
    UserDetails userDetails = User.withDefaultPasswordEncoder()
        .username("user")
        .password("password")
        .roles("USER")
        .build();
    
    // 메모리에 사용자 정보를 보관
    return new InMemoryUserDetailsManager(userDetails);
  }
}

