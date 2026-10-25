// 自动生成的 PoC 骨架（M45 PoC 合成器）
// 规则层判定：sqli = True
// 目标位置：GenController.java:195
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
public class Gencontroller_createPocTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void sqlInjectionPayloadRejected() throws Exception {
        mockMvc.perform(get("/tool/gen/createTable").param("id", "' OR '1'='1' --"))
            .andExpect(status().is4xxClientError());
    }
}
