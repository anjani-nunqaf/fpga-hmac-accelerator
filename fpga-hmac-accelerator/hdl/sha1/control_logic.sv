//SHA-1
`default_nettype none

module control_logic (
    input  logic         clk,
    input  logic         rst,
    //--- Antarmuka AXI-Lite & SHA1
    input  logic [15:0] s_axil_awaddr, input  logic s_axil_awvalid, output logic s_axil_awready,
    input  logic [31:0] s_axil_wdata,  input  logic [3:0]  s_axil_wstrb, input  logic s_axil_wvalid,
    output logic s_axil_wready, output logic [1:0]  s_axil_bresp, output logic s_axil_bvalid,
    input  logic s_axil_bready, input  logic [15:0] s_axil_araddr, input  logic s_axil_arvalid,
    output logic s_axil_arready, output logic [31:0] s_axil_rdata,  output logic [1:0]  s_axil_rresp,
    output logic s_axil_rvalid,  input  logic s_axil_rready,
    output logic         sha_init_o,
    output logic         sha_next_o,
    output logic [511:0] sha_block_o,
    input  logic [159:0] sha_digest_i,
    input  logic         sha_digest_valid_i,
    input  logic         sha_ready_i
);

    // Peta Register
    localparam ADDR_CTRL   = 16'h0000;
    localparam ADDR_STATUS = 16'h0004;
    localparam ADDR_KEY    = 16'h0010;
    localparam ADDR_MSG    = 16'h0050; // 0x10 + 64 bytes
    localparam ADDR_DIGEST = 16'h0090; // 0x50 + 64 bytes
    localparam [511:0] IPAD = {64{8'h36}};
    localparam [511:0] OPAD = {64{8'h5C}};

    logic [511:0] key_buffer, msg_buffer;
    logic [159:0] inner_hash_reg, final_digest_reg; 
    logic status_done_reg, start_cmd;

    typedef enum { IDLE, INNER_HASH1, INNER_HASH2, INNER_HASH_PAD, INNER_HASH_WAIT,
                   OUTER_HASH1, OUTER_HASH2, OUTER_HASH_WAIT, DONE } state_t;
    state_t state_reg, state_next;
    
    always_ff @(posedge clk or posedge rst) begin
        if (rst) state_reg <= IDLE;
        else     state_reg <= state_next;
    end
    
    always_comb begin
        state_next = state_reg; sha_init_o = 1'b0; sha_next_o = 1'b0; sha_block_o = '0;
        case(state_reg)
            IDLE:           if (start_cmd) state_next = INNER_HASH1;
            INNER_HASH1:    if (sha_ready_i) begin sha_init_o = 1'b1; sha_block_o = key_buffer ^ IPAD; state_next = INNER_HASH2; end
            INNER_HASH2:    if (sha_ready_i) begin sha_next_o = 1'b1; sha_block_o = msg_buffer; state_next = INNER_HASH_PAD; end
            INNER_HASH_PAD: if (sha_ready_i) begin sha_next_o = 1'b1; sha_block_o = {1'b1, 447'b0, 64'd1024}; state_next = INNER_HASH_WAIT; end
            INNER_HASH_WAIT:if (sha_digest_valid_i) state_next = OUTER_HASH1;
            OUTER_HASH1:    if (sha_ready_i) begin sha_init_o = 1'b1; sha_block_o = key_buffer ^ OPAD; state_next = OUTER_HASH2; end
            OUTER_HASH2:    if (sha_ready_i) begin sha_next_o = 1'b1; sha_block_o = {inner_hash_reg, 1'b1, 287'b0, 64'd672}; state_next = OUTER_HASH_WAIT; end
            OUTER_HASH_WAIT:if (sha_digest_valid_i) state_next = DONE;
            DONE:           state_next = IDLE;
        endcase
    end
    
    always_ff @(posedge clk or posedge rst) begin
        if (rst) begin
            inner_hash_reg <= 160'b0; final_digest_reg <= 160'b0; status_done_reg <= 1'b0;
        end else begin
            if (state_reg == INNER_HASH_WAIT && sha_digest_valid_i) inner_hash_reg <= sha_digest_i;
            if (state_reg == OUTER_HASH_WAIT && sha_digest_valid_i) final_digest_reg <= sha_digest_i;
            if (state_reg == DONE) status_done_reg <= 1'b1;
            else if (start_cmd) status_done_reg <= 1'b0;
        end
    end

    // --- Logika AXI-Lite Slave ---
    logic [31:0] wdata_swapped; logic aw_ready, w_ready, ar_ready;
    logic [15:0] aw_addr, ar_addr; logic b_valid, r_valid;
    always_ff @(posedge clk or posedge rst) begin
        if (rst) start_cmd <= 1'b0; else begin start_cmd <= 1'b0; if (s_axil_wvalid && w_ready && aw_addr == ADDR_CTRL && s_axil_wdata[0]) start_cmd <= 1'b1; end
    end
    assign s_axil_awready = aw_ready; assign s_axil_wready  = w_ready; assign s_axil_bvalid  = b_valid;
    assign s_axil_bresp   = 2'b00;    assign s_axil_arready = ar_ready; assign s_axil_rvalid  = r_valid;
    assign s_axil_rresp   = 2'b00;
    always_ff @(posedge clk or posedge rst) begin
        if (rst) begin aw_ready <= 1'b0; w_ready <= 1'b0; b_valid <= 1'b0; ar_ready <= 1'b0; r_valid <= 1'b0;
        end else begin
            if (~b_valid || s_axil_bready) begin b_valid <= 1'b0; if (~w_ready && s_axil_awvalid) begin aw_ready <= 1'b0; w_ready <= 1'b1; aw_addr <= s_axil_awaddr; end else aw_ready <= 1'b1; end
            if (s_axil_wvalid && w_ready) begin w_ready <= 1'b0; b_valid <= 1'b1; wdata_swapped = {s_axil_wdata[7:0], s_axil_wdata[15:8], s_axil_wdata[23:16], s_axil_wdata[31:24]}; if (aw_addr >= ADDR_KEY && aw_addr < ADDR_MSG) key_buffer[(511 - (aw_addr - ADDR_KEY)*8) -: 32] <= wdata_swapped; if (aw_addr >= ADDR_MSG && aw_addr < ADDR_DIGEST) msg_buffer[(511 - (aw_addr - ADDR_MSG)*8) -: 32] <= wdata_swapped; end
            if (~r_valid || s_axil_rready) begin r_valid <= 1'b0; ar_ready <= 1'b1; end
            if (s_axil_arvalid && ar_ready) begin ar_ready <= 1'b0; r_valid <= 1'b1; ar_addr <= s_axil_araddr; end
        end
    end
    always_comb begin
        s_axil_rdata = 32'hDEADBEEF;
        if (s_axil_araddr == ADDR_STATUS) begin s_axil_rdata = {30'b0, (state_reg == IDLE), status_done_reg};
        end else if (s_axil_araddr >= ADDR_DIGEST && s_axil_araddr < (ADDR_DIGEST + 20)) begin // 20 byte digest
            s_axil_rdata = {final_digest_reg[159-((s_axil_araddr-ADDR_DIGEST)*8)-24-:8], final_digest_reg[159-((s_axil_araddr-ADDR_DIGEST)*8)-16-:8], final_digest_reg[159-((s_axil_araddr-ADDR_DIGEST)*8)-8-:8], final_digest_reg[159-((s_axil_araddr-ADDR_DIGEST)*8)-:8]};
        end
    end
endmodule