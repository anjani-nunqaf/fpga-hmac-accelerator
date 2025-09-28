//SHA-256
`default_nettype none

module control_logic (
    input  logic         clk,
    input  logic         rst,

    //--- Antarmuka AXI-Lite Slave
    input  logic [15:0] s_axil_awaddr,
    input  logic         s_axil_awvalid,
    output logic         s_axil_awready,
    input  logic [31:0] s_axil_wdata,
    input  logic [3:0]  s_axil_wstrb,
    input  logic         s_axil_wvalid,
    output logic         s_axil_wready,
    output logic [1:0]  s_axil_bresp,
    output logic         s_axil_bvalid,
    input  logic         s_axil_bready,
    input  logic [15:0] s_axil_araddr,
    input  logic         s_axil_arvalid,
    output logic         s_axil_arready,
    output logic [31:0] s_axil_rdata,
    output logic [1:0]  s_axil_rresp,
    output logic         s_axil_rvalid,
    input  logic         s_axil_rready,

    //--- Antarmuka ke SHA256 Core
    output logic         sha_init_o,
    output logic         sha_next_o,
    output logic [511:0] sha_block_o,
    input  logic [255:0] sha_digest_i,
    input  logic         sha_digest_valid_i,
    input  logic         sha_ready_i
);

    // Peta Register
    localparam ADDR_CTRL      = 16'h00;
    localparam ADDR_KEY       = 16'h10;
    localparam ADDR_MSG       = 16'h50;
    localparam ADDR_DIGEST    = 16'h90;
    localparam ADDR_DBG_KEY_R = 16'h110;
    localparam ADDR_DBG_MSG_R = 16'h150;
    localparam ADDR_DBG_INNER_R = 16'h190;
    
    // Konstanta HMAC
    localparam [511:0] IPAD = 512'h36363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636;
    localparam [511:0] OPAD = 512'h5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C;

    logic [511:0] key_buffer;
    logic [511:0] msg_buffer;
    logic [255:0] inner_hash_reg;
    logic [255:0] final_digest_reg;
    logic         status_done_reg;
    logic         start_cmd;
    logic [31:0]  wdata_swapped;
    
    typedef enum {IDLE, INNER_HASH1, INNER_HASH2, INNER_HASH_PAD, INNER_HASH_WAIT,
                  OUTER_HASH1, OUTER_HASH2, OUTER_HASH_WAIT, DONE} state_t;
    state_t state_reg, state_next;

    always_ff @(posedge clk or posedge rst) begin
        if (rst) state_reg <= IDLE;
        else     state_reg <= state_next;
    end
    
    always_comb begin
        state_next = state_reg; sha_init_o = 1'b0; sha_next_o = 1'b0; sha_block_o = '0;
        case(state_reg)
            IDLE: if (start_cmd) state_next = INNER_HASH1;
            INNER_HASH1:    if (sha_ready_i) begin sha_init_o = 1'b1; sha_block_o = key_buffer ^ IPAD; state_next = INNER_HASH2; end
            INNER_HASH2:    if (sha_ready_i) begin sha_next_o = 1'b1; sha_block_o = msg_buffer; state_next = INNER_HASH_PAD; end
            INNER_HASH_PAD: if (sha_ready_i) begin sha_next_o = 1'b1; sha_block_o = {1'b1, 447'b0, 64'd1024}; state_next = INNER_HASH_WAIT; end
            INNER_HASH_WAIT: if (sha_digest_valid_i) state_next = OUTER_HASH1;
            
            OUTER_HASH1: if (sha_ready_i) begin sha_init_o = 1'b1; sha_block_o = key_buffer ^ OPAD; state_next = OUTER_HASH2; end
            OUTER_HASH2: if (sha_ready_i) begin
                sha_next_o  = 1'b1;
                sha_block_o = {inner_hash_reg, 1'b1, 191'b0, 64'd768};
                state_next  = OUTER_HASH_WAIT;
            end
            OUTER_HASH_WAIT: if (sha_digest_valid_i) state_next = DONE;
            DONE: state_next = IDLE;
        endcase
    end
    
    
    always_ff @(posedge clk or posedge rst) begin
        if (rst) begin
            inner_hash_reg <= 256'b0;
            final_digest_reg <= 256'b0;
            status_done_reg <= 1'b0;
        end
        else begin
            if (state_reg == INNER_HASH_WAIT && sha_digest_valid_i) begin
                inner_hash_reg <= sha_digest_i;
            end
            
            if (state_reg == OUTER_HASH_WAIT && sha_digest_valid_i) begin
                final_digest_reg <= sha_digest_i;
            end

            if (state_reg == DONE) begin
                status_done_reg <= 1'b1;
            end
            else if (start_cmd) begin
                status_done_reg <= 1'b0;
            end
        end
    end

    // --- Logika AXI-Lite Slave ---
    logic aw_ready, w_ready, ar_ready;
    logic [15:0] aw_addr, ar_addr;
    logic b_valid, r_valid;
    
    assign s_axil_awready = aw_ready;
    assign s_axil_wready  = w_ready;
    assign s_axil_bvalid  = b_valid;
    assign s_axil_bresp   = 2'b00;
    assign s_axil_arready = ar_ready;
    assign s_axil_rvalid  = r_valid;
    assign s_axil_rresp   = 2'b00;
    
    always_comb begin
        s_axil_rdata = 32'hDEADBEEF;
        case (ar_addr)
            ADDR_CTRL: s_axil_rdata = {31'b0, status_done_reg};
            default:
                if (ar_addr >= ADDR_DIGEST && ar_addr < ADDR_DBG_KEY_R) begin
                    s_axil_rdata = {final_digest_reg[255 - ((ar_addr-ADDR_DIGEST) * 8) - 24 -: 8],
                                    final_digest_reg[255 - ((ar_addr-ADDR_DIGEST) * 8) - 16 -: 8],
                                    final_digest_reg[255 - ((ar_addr-ADDR_DIGEST) * 8) - 8 -: 8],
                                    final_digest_reg[255 - ((ar_addr-ADDR_DIGEST) * 8) -: 8]};
                end
                else if (ar_addr >= ADDR_DBG_KEY_R && ar_addr < ADDR_DBG_MSG_R) begin
                    s_axil_rdata = {key_buffer[511 - ((ar_addr-ADDR_DBG_KEY_R) * 8) - 24 -: 8],
                                    key_buffer[511 - ((ar_addr-ADDR_DBG_KEY_R) * 8) - 16 -: 8],
                                    key_buffer[511 - ((ar_addr-ADDR_DBG_KEY_R) * 8) - 8 -: 8],
                                    key_buffer[511 - ((ar_addr-ADDR_DBG_KEY_R) * 8) -: 8]};
                end
                else if (ar_addr >= ADDR_DBG_MSG_R && ar_addr < ADDR_DBG_INNER_R) begin
                    s_axil_rdata = {msg_buffer[511 - ((ar_addr-ADDR_DBG_MSG_R) * 8) - 24 -: 8],
                                    msg_buffer[511 - ((ar_addr-ADDR_DBG_MSG_R) * 8) - 16 -: 8],
                                    msg_buffer[511 - ((ar_addr-ADDR_DBG_MSG_R) * 8) - 8 -: 8],
                                    msg_buffer[511 - ((ar_addr-ADDR_DBG_MSG_R) * 8) -: 8]};
                end
                else if (ar_addr >= ADDR_DBG_INNER_R) begin
                    s_axil_rdata = {inner_hash_reg[255 - ((ar_addr-ADDR_DBG_INNER_R) * 8) - 24 -: 8],
                                    inner_hash_reg[255 - ((ar_addr-ADDR_DBG_INNER_R) * 8) - 16 -: 8],
                                    inner_hash_reg[255 - ((ar_addr-ADDR_DBG_INNER_R) * 8) - 8 -: 8],
                                    inner_hash_reg[255 - ((ar_addr-ADDR_DBG_INNER_R) * 8) -: 8]};
                end
        endcase
    end

    always_ff @(posedge clk or posedge rst) begin
        if (rst) begin
            aw_ready <= 1'b0; w_ready <= 1'b0; b_valid <= 1'b0; start_cmd <= 1'b0; ar_ready <= 1'b0; r_valid <= 1'b0;
        end else begin
            start_cmd <= 1'b0;
            if (~b_valid || s_axil_bready) begin
                b_valid <= 1'b0;
                if (~w_ready && s_axil_awvalid) begin aw_ready <= 1'b0; w_ready <= 1'b1; aw_addr <= s_axil_awaddr;
                end else aw_ready <= 1'b1;
            end
            if (s_axil_wvalid && w_ready) begin
                w_ready <= 1'b0; b_valid <= 1'b1;
                wdata_swapped = {s_axil_wdata[7:0], s_axil_wdata[15:8], s_axil_wdata[23:16], s_axil_wdata[31:24]};
                if (aw_addr >= ADDR_KEY && aw_addr < ADDR_MSG)
                    key_buffer[(511 - (aw_addr - ADDR_KEY)*8) -: 32] <= wdata_swapped;
                if (aw_addr >= ADDR_MSG && aw_addr < ADDR_DIGEST)
                    msg_buffer[(511 - (aw_addr - ADDR_MSG)*8) -: 32] <= wdata_swapped;
                if (aw_addr == ADDR_CTRL && s_axil_wdata[0]) start_cmd <= 1'b1;
            end
            if (~r_valid || s_axil_rready) begin r_valid <= 1'b0; ar_ready <= 1'b1; end
            if (s_axil_arvalid && ar_ready) begin ar_ready <= 1'b0; r_valid <= 1'b1; ar_addr <= s_axil_araddr; end
        end
    end
endmodule
