package bitcamp.myapp.security05;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Base64.Encoder;
import org.springframework.security.crypto.password.PasswordEncoder;

// 사용자가 입력한 암호와 DB에 저장된 암호를 비교
public class SimplePasswordEncoder02 implements PasswordEncoder {

  @Override
  public String encode(CharSequence rawPassword) {
    // 사용자가 입력한 암호를 암호화하여 리턴
    Encoder encoder = Base64.getEncoder();
    try {
      return encoder.encodeToString(rawPassword.toString().getBytes(StandardCharsets.UTF_8.name()));
    } catch (UnsupportedEncodingException e) {
      throw new RuntimeException("지원하지 않는 Charset 입니다.");
    }
  }

  @Override
  public boolean matches(CharSequence rawPassword, String encodedPassword) {
    // DB에 보관된 암호와 사용자가 입력한 암호를 비교
    return encodedPassword.equals(this.encode(rawPassword));
  }
}
