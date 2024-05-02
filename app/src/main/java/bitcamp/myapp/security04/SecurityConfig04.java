package bitcamp.myapp.security04;

import bitcamp.myapp.service.MemberService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
//
//@Configuration
//@EnableWebSecurity
public class SecurityConfig04 {
  private static final Log log = LogFactory.getLog(SecurityConfig04.class);
  
  public SecurityConfig04(){
    log.debug("SecurityConfig 객체 생성");
  }

  // Spring Security를 처리할 필터 체인을 준비
//  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .authorizeHttpRequests((authorize) -> authorize
            .anyRequest().authenticated() // 어떤 요청에 대해서 적용할지 설정
        )
        .httpBasic(Customizer.withDefaults())  // http 요청
        .formLogin(httpSecurityFormLoginConfigurer -> {
            httpSecurityFormLoginConfigurer
                .loginPage("/auth/form") // 로그인 폼을 제공하는 url
                .loginProcessingUrl("/auth/login") // 로그인을 처리하는 url - Controller의 mapping 주소와 무관 / html에서 주는 action / href 의 주소(url)
                .usernameParameter("email") // 로그인을 수행할 때 사용할 사용자 id or Email (principal) 파라미터 명
                .passwordParameter("password") // 로그인을 수행할 때 사용용할 사용자 암호(credential) 파라미터 명
                .defaultSuccessUrl("/home", true) // 로그인 성공 후 redirect 할 url
                .permitAll(); // 모든 권한 부여
          }
        ); // 로그인 폼

    // HttpSecurity 객체에 설정한대로 동작할 수 있는 필터를 구성
    return http.build();
  }
  
  // 사용자 정보를 리턴해주는 객체
//  @Bean
  public UserDetailsService userDetailsService(MemberService memberService) {
    
    // 구현한 UserDetailsService 객체 사용
    // => DB에서 사용자 정보를 가져옴
    
    return new MyUserDetailsService02(memberService);
  }

  // 로그인 폼에서 입력한 암호와 DB에서 꺼낸 암호가 같은지 비교하는 객체 준비
  // => Spring Security는 이 객체를 사용하여 암호를 비교
//  @Bean
  public PasswordEncoder passwordEncoder(){
    return new SimplePasswordEncoder01();
  }
}
