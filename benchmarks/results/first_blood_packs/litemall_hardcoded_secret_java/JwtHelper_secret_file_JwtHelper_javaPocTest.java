// 自动生成的 PoC 骨架（M45 PoC 合成器）
// 规则层判定：hardcoded_secret = True
// 目标位置：JwtHelper.java:1
package poc;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.*;
import static org.hamcrest.Matchers.not;

@SpringBootTest
@AutoConfigureMockMvc
public class Secret_file_jwthelper_javaPocTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void forgedAdminTokenWithHardcodedSecret() throws Exception {
        String forged = io.jsonwebtoken.Jwts.builder()
            .setSubject("admin").claim("role", "admin")
            .signWith(io.jsonwebtoken.SignatureAlgorithm.HS256, "X-Litemall-Token")
            .compact();
        mockMvc.perform(get("/[secret-file] JwtHelper.java")
                .header("Authorization", "Bearer " + forged))
            .andExpect(status().is4xxClientError());
    }
}
