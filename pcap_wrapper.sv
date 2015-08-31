`include "types.sv"


`AXI4_STREAM_STRUCT_DEF(64b, 64)

module pcap_parser ( 
  input   wire                     CLK,
  input   wire                     RST_N,

  input   `AXI4_STREAM_STRUCT(64b) AXIS_PCAP_S,
  output  `AXI4_STREAM_STRUCT(64b) AXIS_RAW_M,

  output  pcap_hdr_t               GLOBAL_HEADER
);



  always @(posedge CLK or negedge RST_N) begin
    if(!RST_N) begin
      RAW.tvalid <= 0;
      RAW.tdata  <= 0;
    end else begin
      RAW.tvalid <= 1;
      RAW.tdata  <= 1;
    end
  end

  assign AXIS_RAW_M.tvalid  = AXIS_PCAP_S.tvalid;
  assign AXIS_RAW_M.tdata   = AXIS_PCAP_S.tdata;
  assign AXIS_PCAP_S.tready = AXIS_RAW_M.tready;

endmodule


module pcap2hwgen ( 
  input  wire           CLK,
  input  wire           RST_N,

  input  wire           PCAP_TVALID,
  output reg            PCAP_TREADY,
  input  wire [63:0]    PCAP_TDATA,
   
  output wire           HWGEN_TVALID,
  input  reg            HWGEN_TREADY,
  output wire [63:0]    HWGEN_TDATA
);
  `AXI4_STREAM_STRUCT(64b) AXIS_PCAP, AXIS_HWGEN;

  assign AXIS_PCAP.tdata  = PCAP_TDATA;
  assign AXIS_PCAP.tvalid = PCAP_TVALID;
  assign PCAP_TREADY      = AXIS_PCAP.tready;

  assign HWGEN_TDATA       = AXIS_HWGEN.tdata;
  assign HWGEN_TVALID      = AXIS_HWGEN.tvalid;
  assign AXIS_HWGEN.tready = HWGEN_TREADY;

  pcap_parser pcap_parser_i (
    .CLK(CLK),
    .RST_N(RST_N),
    .AXIS_PCAP_S(AXIS_PCAP),
    .AXIS_RAW_M(AXIS_HWGEN),
    .GLOBAL_HEADER()
  );

//    if (global_header[0] == 8'hD4 && global_header[1] == 8'hC3 && global_header[2] == 8'hB2) begin
//      $display(" pcap endian: swapped, ms");
//      swapped = 1;
//      toNanos = 32'd1000000;
//    end else if (global_header[0] == 8'hA1 && global_header[1] == 8'hB2 && global_header[2] == 8'hC3) begin
//      $display(" pcap endian: native, ms");
//      swapped = 0;
//      toNanos = 32'd1000000;
//    end else if (global_header[0] == 8'h4D && global_header[1] == 8'h3C && global_header[2] == 8'hb2) begin
//      $display(" pcap endian: swapped, nanos");
//      swapped = 1;
//      toNanos = 32'd1;
//    end else if (global_header[0] == 8'hA1 && global_header[1] == 8'hB2 && global_header[2] == 8'h3c) begin
//      $display(" pcap endian: native, nanos");
//      swapped = 0;
//      toNanos = 32'd1;
//    end else begin
//      $display(" pcap endian: unrecognised format %02x%02x%02x%02x", global_header[0], global_header[1], global_header[2], global_header[3] );
//      $finish_and_return(1);
//    end

endmodule