`default_nettype none

//======================================================================
// fpga_top.sv (Versi untuk HMAC-SHA1)
//======================================================================
module top_fpga (
    input  logic clk,      // Hubungkan ke PIN Clock FPGA Anda

    // Pin I2C fisik (tidak berubah)
    inout  logic i2c_scl,
    inout  logic i2c_sda
);

    // --- Logika Power-on-Reset (tidak berubah) ---
    logic rst;
    logic [7:0] reset_counter = 8'h00;
    always_ff @(posedge clk) begin
        if (reset_counter != 8'hFF) reset_counter <= reset_counter + 1;
    end
    assign rst = (reset_counter == 8'hFF) ? 1'b0 : 1'b1;

    // --- Sinyal Koneksi Internal I2C (tidak berubah) ---
    logic scl_i, scl_o, scl_t;
    logic sda_i, sda_o, sda_t;
    assign scl_i = i2c_scl;
    assign i2c_scl = scl_t ? 1'bz : scl_o;
    assign sda_i = i2c_sda;
    assign i2c_sda = sda_t ? 1'bz : sda_o;

    // AXI-Lite Bus (tidak berubah)
    logic [15:0] axil_awaddr, axil_araddr;
    logic        axil_awvalid, axil_arvalid, axil_awready, axil_arready;
    logic [31:0] axil_wdata, axil_rdata;
    logic [3:0]  axil_wstrb;
    logic        axil_wvalid, axil_rvalid, axil_wready, axil_rready;
    logic [1:0]  axil_bresp, axil_rresp;
    logic        axil_bvalid, axil_bready;

    // --- PERUBAHAN: Ukuran sinyal internal untuk SHA-1 ---
    logic         sha_init, sha_next;
    logic [511:0] sha_block;          // Tetap 512 bit
    logic [159:0] sha_digest;         // Diubah menjadi 160 bit
    logic         sha_digest_valid, sha_ready;

    // --- Instansiasi Modul ---

    // 1. I2C Slave Wrapper (tidak berubah)
    i2c_slave_axil_master #(
        .DATA_WIDTH(32), .ADDR_WIDTH(16)
    ) i2c_wrapper (
        .clk(clk), .rst(rst),
        .i2c_scl_i(scl_i), .i2c_scl_o(scl_o), .i2c_scl_t(scl_t),
        .i2c_sda_i(sda_i), .i2c_sda_o(sda_o), .i2c_sda_t(sda_t),
        .m_axil_awaddr(axil_awaddr), .m_axil_awprot(), .m_axil_awvalid(axil_awvalid), .m_axil_awready(axil_awready),
        .m_axil_wdata(axil_wdata), .m_axil_wstrb(axil_wstrb), .m_axil_wvalid(axil_wvalid), .m_axil_wready(axil_wready),
        .m_axil_bresp(axil_bresp), .m_axil_bvalid(axil_bvalid), .m_axil_bready(axil_bready),
        .m_axil_araddr(axil_araddr), .m_axil_arprot(), .m_axil_arvalid(axil_arvalid), .m_axil_arready(axil_arready),
        .m_axil_rdata(axil_rdata), .m_axil_rresp(axil_rresp), .m_axil_rvalid(axil_rvalid), .m_axil_rready(axil_rready),
        .enable(1'b1), .device_address(7'h50), // Ganti device_address jika perlu
        .bus_active(), .bus_addressed(), .busy()
    );

    // 2. Logika Kontrol HMAC-SHA1
    // PERUBAHAN: Pastikan Anda memanggil modul control_logic versi SHA-1
    control_logic FSM_SHA1 (
        .clk(clk), .rst(rst),
        .s_axil_awaddr(axil_awaddr), .s_axil_awvalid(axil_awvalid), .s_axil_awready(axil_awready),
        .s_axil_wdata(axil_wdata), .s_axil_wstrb(axil_wstrb), .s_axil_wvalid(axil_wvalid), .s_axil_wready(axil_wready),
        .s_axil_bresp(axil_bresp), .s_axil_bvalid(axil_bvalid), .s_axil_bready(axil_bready),
        .s_axil_araddr(axil_araddr), .s_axil_arvalid(axil_arvalid), .s_axil_arready(axil_arready),
        .s_axil_rdata(axil_rdata), .s_axil_rresp(axil_rresp), .s_axil_rvalid(axil_rvalid), .s_axil_rready(axil_rready),
        .sha_init_o(sha_init),
        .sha_next_o(sha_next),
        .sha_block_o(sha_block),
        .sha_digest_i(sha_digest),
        .sha_digest_valid_i(sha_digest_valid),
        .sha_ready_i(sha_ready)
    );

    // 3. SHA-1 Core Engine
    // PERUBAHAN: Instansiasi sha1_core bukan sha256_core
    sha1_core sha1_engine (
        .clk(clk), 
        .reset_n(~rst),
        .init(sha_init), 
        .next(sha_next),
        .block(sha_block),
        .ready(sha_ready),
        .digest(sha_digest),
        .digest_valid(sha_digest_valid)
    );

endmodule