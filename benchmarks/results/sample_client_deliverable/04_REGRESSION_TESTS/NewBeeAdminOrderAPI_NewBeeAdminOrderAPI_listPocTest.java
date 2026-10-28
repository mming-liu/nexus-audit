// 自动生成的 PoC 骨架（M45 PoC 合成器）
// 规则层判定：cors = True
// 目标位置：NewBeeAdminOrderAPI.java:51
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
public class Newbeeadminorderapi_listPocTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void corsEvilOriginNotReflected() throws Exception {
        mockMvc.perform(options("/manage-api/v1/orders")
                .header("Origin", "https://evil.example")
                .header("Access-Control-Request-Method", "GET"))
            .andExpect(header().string("Access-Control-Allow-Origin",
                                       not("https://evil.example")));
    }
}
