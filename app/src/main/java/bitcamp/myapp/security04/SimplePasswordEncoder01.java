package bitcamp.myapp.security04;

import org.springframework.security.crypto.password.PasswordEncoder;

// 사용자가 입력한 암호와 DB에 저장된 암호를 비교
public class SimplePasswordEncoder01 implements PasswordEncoder {

  @Override
  public String encode(CharSequence rawPassword) {
    // 사용자가 입력한 암호를 암호화하여 리턴

    return rawPassword.toString();
  }

  @Override
  public boolean matches(CharSequence rawPassword, String encodedPassword) {
    // DB에 보관된 암호와 사용자가 입력한 암호를 비교
    return encodedPassword.equals(this.encode(rawPassword));
  }
}
