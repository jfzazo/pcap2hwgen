`timescale 1ns / 1ps


module eth_crc_8
(
    input  wire [7:0] data_in,
    input  wire [31:0] crc_state,
    output wire [31:0] crc_next
);

`include "crc32.v"
assign crc_next = crc_iteration( 8, crc_state, { 120'h0, data_in} );

endmodule

module eth_crc_16
(
    input  wire [15:0] data_in,
    input  wire [31:0] crc_state,
    output wire [31:0] crc_next
);

`include "crc32.v"
assign crc_next = crc_iteration( 16, crc_state, { 112'h0, data_in} );

endmodule

module eth_crc_24
(
    input  wire [23:0] data_in,
    input  wire [31:0] crc_state,
    output wire [31:0] crc_next
);

`include "crc32.v"
assign crc_next = crc_iteration( 24, crc_state, { 104'h0, data_in} );

endmodule

module eth_crc_32
(
    input  wire [31:0] data_in,
    input  wire [31:0] crc_state,
    output wire [31:0] crc_next
);

`include "crc32.v"
assign crc_next = crc_iteration( 32, crc_state, { 96'h0, data_in} );

endmodule

module eth_crc_40
(
    input  wire [39:0] data_in,
    input  wire [31:0] crc_state,
    output wire [31:0] crc_next
);

`include "crc32.v"
assign crc_next = crc_iteration( 40, crc_state, { 88'h0, data_in} );

endmodule

module eth_crc_48
(
    input  wire [47:0] data_in,
    input  wire [31:0] crc_state,
    output wire [31:0] crc_next
);

`include "crc32.v"
assign crc_next = crc_iteration( 48, crc_state, { 80'h0, data_in} );

endmodule

module eth_crc_56
(
    input  wire [55:0] data_in,
    input  wire [31:0] crc_state,
    output wire [31:0] crc_next
);

`include "crc32.v"
assign crc_next = crc_iteration( 56, crc_state, { 72'h0, data_in} );

endmodule

module eth_crc_64
(
    input  wire [63:0] data_in,
    input  wire [31:0] crc_state,
    output wire [31:0] crc_next
);

`include "crc32.v"
assign crc_next = crc_iteration( 64, crc_state, { 64'h0, data_in} );

endmodule

module eth_crc_72
(
    input  wire [71:0] data_in,
    input  wire [31:0] crc_state,
    output wire [31:0] crc_next
);

`include "crc32.v"
assign crc_next = crc_iteration( 72, crc_state, { 56'h0, data_in} );

endmodule

module eth_crc_80
(
    input  wire [79:0] data_in,
    input  wire [31:0] crc_state,
    output wire [31:0] crc_next
);

`include "crc32.v"
assign crc_next = crc_iteration( 80, crc_state, { 48'h0, data_in} );

endmodule


module eth_crc_88
(
    input  wire [87:0] data_in,
    input  wire [31:0] crc_state,
    output wire [31:0] crc_next
);

`include "crc32.v"
assign crc_next = crc_iteration( 88, crc_state, { 40'h0, data_in} );

endmodule

module eth_crc_96
(
    input  wire [95:0] data_in,
    input  wire [31:0] crc_state,
    output wire [31:0] crc_next
);

`include "crc32.v"
assign crc_next = crc_iteration( 96, crc_state, { 32'h0, data_in} );

endmodule


module eth_crc_104
(
    input  wire [103:0] data_in,
    input  wire [31:0] crc_state,
    output wire [31:0] crc_next
);

`include "crc32.v"
assign crc_next = crc_iteration( 104, crc_state, { 24'h0, data_in} );

endmodule

module eth_crc_112
(
    input  wire [111:0] data_in,
    input  wire [31:0] crc_state,
    output wire [31:0] crc_next
);

`include "crc32.v"
assign crc_next = crc_iteration( 112, crc_state, { 16'h0, data_in} );

endmodule

module eth_crc_120
(
    input  wire [119:0] data_in,
    input  wire [31:0] crc_state,
    output wire [31:0] crc_next
);

`include "crc32.v"
assign crc_next = crc_iteration( 120, crc_state, { 8'h0, data_in} );

endmodule


module eth_crc_128
(
    input  wire [127:0] data_in,
    input  wire [31:0] crc_state,
    output wire [31:0] crc_next
);

`include "crc32.v"
assign crc_next = crc_iteration( 128, crc_state,  data_in );

endmodule


/*
 * AXI4-Stream Ethernet FCS Generator
 */
module axis_eth_fcs
(
    input  wire        clk,
    input  wire        rst,
    
    /*
     * AXI input
     */
    input  wire [127:0]  input_axis_tdata,
    input  wire [15:0]   input_axis_tstrb,
    input  wire          input_axis_tvalid,
    output wire          input_axis_tready,
    input  wire          input_axis_tlast,
    
    /*
     * FCS output
     */
    output wire [31:0] output_fcs,
    output wire        output_fcs_valid
);


reg [31:0] crc_state = 32'hFFFFFFFF;
reg [31:0] fcs_reg = 0;
reg fcs_valid_reg = 0;

wire [31:0] crc_next;
wire [31:0] crc_next_array [15:0];

assign input_axis_tready = 1;
assign output_fcs = fcs_reg;
assign output_fcs_valid = fcs_valid_reg;


always @(posedge clk or posedge rst) begin
    if (rst) begin
        crc_state <= 32'hFFFFFFFF;
        fcs_reg <= 0;
        fcs_valid_reg <= 0;
    end else begin
        fcs_valid_reg <= 0;
        if (input_axis_tvalid) begin
            if (input_axis_tlast) begin
                crc_state <= 32'hFFFFFFFF;
                fcs_reg <= ~crc_next;
                fcs_valid_reg <= 1;
            end else begin
                crc_state <= crc_next;
            end
        end
    end
end

eth_crc_8 eth_crc_8_inst (
    .data_in(input_axis_tdata[7:0]),
    .crc_state(crc_state),
    .crc_next(crc_next_array[0])
);

eth_crc_16 eth_crc_16_inst (
    .data_in(input_axis_tdata[15:0]),
    .crc_state(crc_state),
    .crc_next(crc_next_array[1])
);

eth_crc_24 eth_crc_24_inst (
    .data_in(input_axis_tdata[23:0]),
    .crc_state(crc_state),
    .crc_next(crc_next_array[2])
);

eth_crc_32 eth_crc_32_inst (
    .data_in(input_axis_tdata[31:0]),
    .crc_state(crc_state),
    .crc_next(crc_next_array[3])
);

eth_crc_40 eth_crc_40_inst (
    .data_in(input_axis_tdata[39:0]),
    .crc_state(crc_state),
    .crc_next(crc_next_array[4])
);

eth_crc_48 eth_crc_48_inst (
    .data_in(input_axis_tdata[47:0]),
    .crc_state(crc_state),
    .crc_next(crc_next_array[5])
);

eth_crc_56 eth_crc_56_inst (
    .data_in(input_axis_tdata[55:0]),
    .crc_state(crc_state),
    .crc_next(crc_next_array[6])
);

eth_crc_64 eth_crc_64_inst (
    .data_in(input_axis_tdata[63:0]),
    .crc_state(crc_state),
    .crc_next(crc_next_array[7])
);

eth_crc_72 eth_crc_72_inst (
    .data_in(input_axis_tdata[71:0]),
    .crc_state(crc_state),
    .crc_next(crc_next_array[8])
);
eth_crc_80 eth_crc_80_inst (
    .data_in(input_axis_tdata[79:0]),
    .crc_state(crc_state),
    .crc_next(crc_next_array[9])
);
eth_crc_88 eth_crc_88_inst (
    .data_in(input_axis_tdata[87:0]),
    .crc_state(crc_state),
    .crc_next(crc_next_array[10])
);
eth_crc_96 eth_crc_96_inst (
    .data_in(input_axis_tdata[95:0]),
    .crc_state(crc_state),
    .crc_next(crc_next_array[11])
);
eth_crc_104 eth_crc_104_inst (
    .data_in(input_axis_tdata[103:0]),
    .crc_state(crc_state),
    .crc_next(crc_next_array[12])
);
eth_crc_112 eth_crc_112_inst (
    .data_in(input_axis_tdata[111:0]),
    .crc_state(crc_state),
    .crc_next(crc_next_array[13])
);
eth_crc_120 eth_crc_120_inst (
    .data_in(input_axis_tdata[119:0]),
    .crc_state(crc_state),
    .crc_next(crc_next_array[14])
);
eth_crc_128 eth_crc_128_inst (
    .data_in(input_axis_tdata),
    .crc_state(crc_state),
    .crc_next(crc_next_array[15])
);


assign crc_next = input_axis_tstrb == 16'h0001 ? crc_next_array[0] :
                  input_axis_tstrb == 16'h0003 ? crc_next_array[1] :
                  input_axis_tstrb == 16'h0007 ? crc_next_array[2] :
                  input_axis_tstrb == 16'h000F ? crc_next_array[3] :
                  input_axis_tstrb == 16'h001F ? crc_next_array[4] :
                  input_axis_tstrb == 16'h003F ? crc_next_array[5] :
                  input_axis_tstrb == 16'h007F ? crc_next_array[6] :
                  input_axis_tstrb == 16'h00FF ? crc_next_array[7] :
                  input_axis_tstrb == 16'h01FF ? crc_next_array[8] :
                  input_axis_tstrb == 16'h03FF ? crc_next_array[9] :
                  input_axis_tstrb == 16'h07FF ? crc_next_array[10] :
                  input_axis_tstrb == 16'h0FFF ? crc_next_array[11] :
                  input_axis_tstrb == 16'h1FFF ? crc_next_array[12] :
                  input_axis_tstrb == 16'h3FFF ? crc_next_array[13] :
                  input_axis_tstrb == 16'h7FFF ? crc_next_array[14] :
                  input_axis_tstrb == 16'hFFFF ? crc_next_array[15] :
                  32'h0;


endmodule

