`timescale 1ns/1ps

`include "types.sv"
import definitions::*;

`AXI4_STREAM_STRUCT_DEF(128b, 128)

module pcap_gheader_parser ( 
  input   wire                     CLK,
  input   wire                     RST_N,

  input   `AXI4_STREAM_STRUCT(128b) AXIS_PCAP_S,
  output  `AXI4_STREAM_STRUCT(128b) AXIS_RAW_M,

  output  pcap_hdr_t               GLOBAL_HEADER,
  output  wire                     GLOBAL_HEADER_VALID
);

  logic [1:0] gheader_parser_state;
  logic is_gheader_valid = (gheader_parser_state == 2'h2) 
                        || (AXIS_PCAP_S.tvalid && (gheader_parser_state == 2'h1));
  
  always @(posedge CLK or negedge RST_N) begin
    if(!RST_N) begin
      gheader_parser_state <= 2'h0;
      GLOBAL_HEADER        <= '{default:0};
    end else begin
      case(gheader_parser_state)
        2'h0: begin
          if( AXIS_PCAP_S.tvalid ) begin
            gheader_parser_state        <= 2'h1;
            GLOBAL_HEADER.magic_numer   <= AXIS_PCAP_S.tdata[31:0]; 
            GLOBAL_HEADER.version_major <= AXIS_PCAP_S.tdata[47:32]; 
            GLOBAL_HEADER.version_minor <= AXIS_PCAP_S.tdata[63:48];
            GLOBAL_HEADER.thiszone      <= AXIS_PCAP_S.tdata[95:64]; 
            GLOBAL_HEADER.sigfigs       <= AXIS_PCAP_S.tdata[127:96]; 
          end else begin 
            gheader_parser_state <= gheader_parser_state;
          end
        end
        2'h1: begin
          if( AXIS_PCAP_S.tvalid ) begin
            gheader_parser_state     <= 2'h2; 
            GLOBAL_HEADER.snaplen   <= AXIS_PCAP_S.tdata[31:0]; 
            GLOBAL_HEADER.network   <= AXIS_PCAP_S.tdata[63:32]; 
          end else begin 
            gheader_parser_state <= gheader_parser_state;
          end
        end
        2'h2: begin // Preserve the state until a reset.
        end
        default: begin
          gheader_parser_state <= 2'h0;
        end
      endcase
    end
  end  


  assign AXIS_RAW_M.tdata   = AXIS_PCAP_S.tdata;
  assign AXIS_RAW_M.tstrb   = gheader_parser_state == 2'h2 ? 16'hFFFF : 16'hFF00;
  assign AXIS_RAW_M.tvalid  = is_gheader_valid ?
                                      AXIS_PCAP_S.tvalid
                                      : 1'b0;
  assign AXIS_PCAP_S.tready = is_gheader_valid ? 
                                      AXIS_RAW_M.tready
                                      : 1'b1;
  assign GLOBAL_HEADER_VALID = is_gheader_valid;
endmodule


module pcap_lheader_parser ( 
  input   wire                     CLK,
  input   wire                     RST_N,

  input   `AXI4_STREAM_STRUCT(128b) AXIS_PCAP_S,
  output  `AXI4_STREAM_STRUCT(128b) AXIS_RAW_M,

  output   pcaprec_hdr_t            LOCAL_HEADER,
  output   wire                     LOCAL_HEADER_VALID
);

  logic [1:0] lheader_parser_state;
  logic is_lheader_valid = lheader_parser_state == 2'b2
                         || (AXIS_PCAP_S.tvalid & ( lheader_parser_state  == 2'h1));
  
  always @(posedge CLK or negedge RST_N) begin
    if(!RST_N) begin
      lheader_parser_state <= 2'h0;
      LOCAL_HEADER        <= '{default:0};
    end else begin
      case(lheader_parser_state)
        2'h0: begin
          if( AXIS_PCAP_S.tvalid && AXIS_PCAP_S.tstrb == 16'hFFFF) begin
            lheader_parser_state  <= 2'h2;
            LOCAL_HEADER.ts_sec   <= AXIS_PCAP_S.tdata[31:0]; 
            LOCAL_HEADER.ts_usec  <= AXIS_PCAP_S.tdata[63:32]; 
            LOCAL_HEADER.incl_len <= AXIS_PCAP_S.tdata[95:64]; 
            LOCAL_HEADER.orig_len <= AXIS_PCAP_S.tdata[128:96];
          end else if(AXIS_PCAP_S.tvalid) begin 
            lheader_parser_state  <= 2'h1;
            LOCAL_HEADER.ts_sec   <= AXIS_PCAP_S.tdata[95:64]; 
            LOCAL_HEADER.ts_usec  <= AXIS_PCAP_S.tdata[128:96]; 
          end else begin 
            lheader_parser_state <= lheader_parser_state;
          end
        end
        2'h1: begin
          if( AXIS_PCAP_S.tvalid ) begin
            lheader_parser_state    <= 2'h2;
            LOCAL_HEADER.incl_len   <= AXIS_PCAP_S.tdata[31:0]; 
            LOCAL_HEADER.orig_len   <= AXIS_PCAP_S.tdata[63:32];
          end else begin 
            lheader_parser_state <= lheader_parser_state;
          end
        end
        2'h2: begin // Preserve the state until next packet.
        end
        default: begin
          lheader_parser_state <= 2'h0;
        end
      endcase
    end
  end  


  assign AXIS_RAW_M.tdata   = AXIS_PCAP_S.tdata;
  assign AXIS_RAW_M.tvalid  = is_lheader_valid ?
                                      AXIS_PCAP_S.tvalid
                                      : 1'b0;
  assign AXIS_RAW_M.tstrb   = lheader_parser_state == 2'h2 ? 16'hFFFF : 16'hFF00;

  assign AXIS_PCAP_S.tready = is_lheader_valid ? 
                                      AXIS_RAW_M.tready
                                      : 1'b1;
  assign LOCAL_HEADER_VALID = is_lheader_valid;
endmodule


module compute_fcs ( 
  input   wire                     CLK,
  input   wire                     RST_N,

  input   `AXI4_STREAM_STRUCT(128b) AXIS_RAW_S,

  input   logic [31:0]             PREV_FCS,
  output  logic [31:0]             FCS

);

  assign AXIS_RAW_S.tready = 1'b1;
  // Synchronous?
  assign FCS = AXIS_RAW_S.tvalid && AXIS_RAW_S.tstrb == 16'hFF00 ? 
              crc32_d64(AXIS_RAW_S.tdata, PREV_FCS)
              : AXIS_RAW_S.tvalid ? 
                  crc32_d128(AXIS_RAW_S.tdata[127:63], PREV_FCS)
                  : 32'h0;
endmodule

module pcap2hwgen ( 
  input  wire           CLK,
  input  wire           RST_N,

  input  wire           PCAP_TVALID,
  output reg            PCAP_TREADY,
  input  wire [127:0]   PCAP_TDATA,
   
  output wire           HWGEN_TVALID,
  input  reg            HWGEN_TREADY,
  output wire [127:0]   HWGEN_TDATA
);
  `AXI4_STREAM_STRUCT(128b) AXIS_PCAP,      // Original PCAP
                           AXIS_PCAP_LVL2, // PCAP without global header
                           AXIS_RAW,       // RAW information of the PCAP file
                           AXIS_HWGEN;     

  pcap_hdr_t    global_header;
  wire          global_header_valid;

  pcaprec_hdr_t local_header;
  wire          local_header_valid;

  assign HWGEN_TDATA = '{default:0};

  pcap_gheader_parser pcap_gheader_parser_i (
    .CLK(CLK),
    .RST_N(RST_N),
    .AXIS_PCAP_S(AXIS_PCAP),
    .AXIS_RAW_M(AXIS_PCAP_LVL2),
    .GLOBAL_HEADER(global_header),
    .GLOBAL_HEADER_VALID(global_header_valid)
  );

  pcap_lheader_parser pcap_lheader_parser_i (
    .CLK(CLK),
    .RST_N(RST_N),
    .AXIS_PCAP_S(AXIS_PCAP_LVL2),
    .AXIS_RAW_M(AXIS_RAW),
    .LOCAL_HEADER(local_header),
    .LOCAL_HEADER_VALID(local_header_valid)
  );


  compute_fcs compute_fcs_i (
    .CLK(CLK),
    .RST_N(RST_N),
    .AXIS_RAW_S(AXIS_RAW),
    .PREV_FCS(prev_fcs),
    .FCS(n_fcs)
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