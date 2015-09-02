`timescale 1ns/1ps

`include "types.sv"

import definitions::*;

`AXI4_STREAM_STRUCT_DEF(128b, 128)
`AXI4_STREAM_READY_STRUCT_DEF(128b, 128)




module pcap_gheader_parser ( 
  input   wire                     CLK,
  input   wire                     RST_N,

  input   `AXI4_STREAM_STRUCT(128b) AXIS_PCAP_S,
  output   `AXI4_STREAM_READY_STRUCT(128b) AXIS_READY_PCAP_S,
  output  `AXI4_STREAM_STRUCT(128b) AXIS_RAW_M,
  input  `AXI4_STREAM_READY_STRUCT(128b) AXIS_READY_RAW_M,

  output  pcap_hdr_t               GLOBAL_HEADER,
  output  wire                     GLOBAL_HEADER_VALID
);

  typedef enum logic[1:0] {WAIT, HDR1, END} gheader_parser_state_t;
  gheader_parser_state_t gheader_parser_state;

  logic is_gheader_valid;
  

  assign is_gheader_valid = (gheader_parser_state == END);
  
  always_ff @(negedge RST_N, posedge CLK) begin
    if(!RST_N) begin
      gheader_parser_state <= WAIT;
    //  GLOBAL_HEADER        <= '{default:0};
    end else begin
      case(gheader_parser_state)
        WAIT: begin
          if( AXIS_PCAP_S.tvalid ) begin
            gheader_parser_state        <= HDR1;
            GLOBAL_HEADER.magic_number   <= AXIS_PCAP_S.tdata[31:0]; 
            GLOBAL_HEADER.version_major <= AXIS_PCAP_S.tdata[47:32]; 
            GLOBAL_HEADER.version_minor <= AXIS_PCAP_S.tdata[63:48];
            GLOBAL_HEADER.thiszone      <= AXIS_PCAP_S.tdata[95:64]; 
            GLOBAL_HEADER.sigfigs       <= AXIS_PCAP_S.tdata[127:96]; 
          end else begin 
            gheader_parser_state <= gheader_parser_state;
          end
        end
        HDR1: begin
          if( AXIS_PCAP_S.tvalid ) begin
            gheader_parser_state     <= END; 
            GLOBAL_HEADER.snaplen   <= AXIS_PCAP_S.tdata[31:0]; 
            GLOBAL_HEADER.network   <= AXIS_PCAP_S.tdata[63:32]; 
          end else begin 
            gheader_parser_state <= gheader_parser_state;
          end
        end
        END: begin // Preserve the state until a reset.
        end
        default: begin
          gheader_parser_state <= WAIT;
        end
      endcase
    end
  end  


  assign AXIS_RAW_M.tdata   = AXIS_PCAP_S.tdata;
  assign AXIS_RAW_M.tstrb   = gheader_parser_state == 2'h2 ? 16'hFFFF : 16'hFF00;
  assign AXIS_RAW_M.tvalid  = (gheader_parser_state == END) || (AXIS_PCAP_S.tvalid && (gheader_parser_state == HDR1));
  assign AXIS_READY_PCAP_S.tready = is_gheader_valid ? 
                                      AXIS_READY_RAW_M.tready
                                      : 1'b1;
  assign GLOBAL_HEADER_VALID = is_gheader_valid;
endmodule


module pcap_lheader_parser ( 
  input   wire                     CLK,
  input   wire                     RST_N,

  input   `AXI4_STREAM_STRUCT(128b) AXIS_PCAP_S,
  output   `AXI4_STREAM_READY_STRUCT(128b) AXIS_READY_PCAP_S,
  output  `AXI4_STREAM_STRUCT(128b) AXIS_RAW_M,
  input  `AXI4_STREAM_READY_STRUCT(128b) AXIS_READY_RAW_M,

  output   pcaprec_hdr_t            LOCAL_HEADER,
  output   wire                     LOCAL_HEADER_VALID
);

  logic [1:0] lheader_parser_state;
  logic is_lheader_valid;
  
  assign is_lheader_valid = lheader_parser_state == 2'h2;


  always_ff @(negedge RST_N or posedge CLK) begin
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
            LOCAL_HEADER.orig_len <= AXIS_PCAP_S.tdata[127:96];
          end else if(AXIS_PCAP_S.tvalid) begin 
            lheader_parser_state  <= 2'h1;
            LOCAL_HEADER.ts_sec   <= AXIS_PCAP_S.tdata[95:64]; 
            LOCAL_HEADER.ts_usec  <= AXIS_PCAP_S.tdata[127:96]; 
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
  assign AXIS_RAW_M.tvalid  = (lheader_parser_state == 2'h2 || (AXIS_PCAP_S.tvalid & lheader_parser_state == 2'h1));
  assign AXIS_RAW_M.tstrb   = lheader_parser_state == 2'h2 ? 16'hFFFF : 16'hFF00;

  assign AXIS_READY_PCAP_S.tready = is_lheader_valid ? 
                                      AXIS_READY_RAW_M.tready
                                      : 1'b1;
  assign LOCAL_HEADER_VALID = is_lheader_valid;
endmodule


module compute_fcs ( 
  input   wire                     CLK,
  input   wire                     RST_N,

  input   `AXI4_STREAM_STRUCT(128b) AXIS_RAW_S,
  output  `AXI4_STREAM_READY_STRUCT(128b) AXIS_READY_RAW_S,

  input   logic [31:0]             PREV_FCS,
  output  logic [31:0]             FCS

);
  `include "crc32.v"

  assign AXIS_READY_RAW_S.tready = 1'b1;
  // Synchronous?
  assign FCS = AXIS_RAW_S.tvalid && AXIS_RAW_S.tstrb == 16'hFF00 ? 
              crc32_d64(AXIS_RAW_S.tdata, PREV_FCS)
              : AXIS_RAW_S.tvalid ? 
                  crc32_d128(AXIS_RAW_S.tdata[127:63], PREV_FCS)
                  : 32'h0;
endmodule



module header2generic ( 
  input   wire                     CLK,
  input   wire                     RST_N,


  input   pcap_hdr_t               GLOBAL_HEADER,
  input   wire                     GLOBAL_HEADER_VALID,

  input   pcaprec_hdr_t            LOCAL_HEADER,
  input   wire                     LOCAL_HEADER_VALID,

  output  genericrec_hdr_t         GENERIC_HEADER,
  output  wire                     INVALID_FORMAT 
);

  wire ns_resolution, us_resolution;
  wire is_valid_format;

  assign us_resolution = GLOBAL_HEADER_VALID & (GLOBAL_HEADER.magic_number == PCAP_US_RESOLUTION_C);
  assign ns_resolution = GLOBAL_HEADER_VALID & (GLOBAL_HEADER.magic_number == PCAP_NS_RESOLUTION_C);
  assign is_valid_format = us_resolution | ns_resolution;


  assign INVALID_FORMAT = !is_valid_format & LOCAL_HEADER_VALID & GLOBAL_HEADER_VALID;

  assign GENERIC_HEADER.incl_len = LOCAL_HEADER_VALID ? LOCAL_HEADER.incl_len : 32'h0;
  assign GENERIC_HEADER.orig_len = LOCAL_HEADER_VALID ? LOCAL_HEADER.incl_len : 32'h0;  // We do NOT expand packets. TODO?
  assign GENERIC_HEADER.valid    = GLOBAL_HEADER_VALID & LOCAL_HEADER_VALID & is_valid_format;      // Support classic PCAP with ns or us resolution
  assign GENERIC_HEADER.ts =  ns_resolution ? 
                              LOCAL_HEADER.ts_sec*1e9 + LOCAL_HEADER.ts_usec 
                              : LOCAL_HEADER.ts_sec*1e9 + LOCAL_HEADER.ts_usec*1e3; 
endmodule

module hwgen_header_creator ( 
  input   wire                      CLK,
  input   wire                      RST_N,

  input   genericrec_hdr_t          GENERIC_HEADER,
  input   wire                      EOF,

  output  hwgen_hdr_t               HWGEN_HEADER,
  output  logic                     HWGEN_HEADER_VALID
);

  logic [63:0]   prev_ts;
  logic [31:0]   prev_sz;

  always_ff @(negedge RST_N or posedge CLK) begin
    if(!RST_N) begin
      prev_ts <= 64'h0;
      prev_sz <= 32'h0;
    end else begin
      if(EOF) begin
        HWGEN_HEADER.orig_len <= prev_ts;
        HWGEN_HEADER.ifg      <= (GENERIC_HEADER.ts-prev_ts)*NS_PER_CYCLE_INV;
        HWGEN_HEADER_VALID    <= 1'b1;
        prev_ts <= GENERIC_HEADER.ts;
        prev_sz <= GENERIC_HEADER.orig_len;
      end else begin
        HWGEN_HEADER_VALID    <= 1'b0;
      end
    end
  end


  assign HWGEN_HEADER.magic_number = HWGEN_MAGIC_NUMBER_C;
endmodule

module packet_parser ( 
  input   wire                      CLK,
  input   wire                      RST_N,

  input   `AXI4_STREAM_STRUCT(128b) AXIS_RAW_S,
  output   `AXI4_STREAM_READY_STRUCT(128b) AXIS_READY_RAW_S,

  output  `AXI4_STREAM_STRUCT(128b) AXIS_RAW_CRC_M,
  input  `AXI4_STREAM_READY_STRUCT(128b) AXIS_READY_RAW_CRC_M,

  input   genericrec_hdr_t          GENERIC_HEADER,
  output  wire                      EOF
);



  logic [31:0] prev_fcs;
  logic [31:0] n_fcs;
  logic [31:0] noctects;

  `AXI4_STREAM_STRUCT(128b) axis_crc;
  `AXI4_STREAM_READY_STRUCT(128b) axis_ready_crc;
  `AXI4_STREAM_STRUCT(128b) axis_fifo;
  `AXI4_STREAM_READY_STRUCT(128b) axis_ready_fifo;

  always_ff @(negedge RST_N or posedge CLK) begin
    if(!RST_N) begin
      noctects   <= 32'h0;
      prev_fcs <= 32'h0;
    end else begin
      if( GENERIC_HEADER.valid & !EOF ) begin
        if(AXIS_RAW_S.tvalid & AXIS_READY_RAW_S.tready) begin
          prev_fcs <= n_fcs;
          noctects <= noctects + AXIS_RAW_S.tstrb [0] + AXIS_RAW_S.tstrb [1] + AXIS_RAW_S.tstrb [2]
                      + AXIS_RAW_S.tstrb [3] + AXIS_RAW_S.tstrb [4] + AXIS_RAW_S.tstrb [5]
                      + AXIS_RAW_S.tstrb [6] + AXIS_RAW_S.tstrb [7] + AXIS_RAW_S.tstrb [8]
                      + AXIS_RAW_S.tstrb [9] + AXIS_RAW_S.tstrb [10] + AXIS_RAW_S.tstrb [11]
                      + AXIS_RAW_S.tstrb [12] + AXIS_RAW_S.tstrb [13] + AXIS_RAW_S.tstrb [14]
                      + AXIS_RAW_S.tstrb [15];
        end else begin
          prev_fcs <= prev_fcs;
        end
      end else begin
        noctects   <= 32'h0;
        prev_fcs   <= 32'h0;
      end
    end
  end

  assign axis_crc.tlast  = 1'b1;
  assign axis_crc.tvalid = 1'b1;
  assign axis_crc.tdata  = prev_fcs;
  assign axis_crc.tstrb  = 16'h000F;

  assign axis_fifo.tvalid = !EOF ? AXIS_RAW_S.tvalid : axis_crc.tvalid;
  assign axis_fifo.tdata  = !EOF ? AXIS_RAW_S.tdata : axis_crc.tdata; 
  assign axis_fifo.tstrb  = !EOF ? AXIS_RAW_S.tstrb : axis_crc.tstrb; 
  assign axis_fifo.tlast  = !EOF ? AXIS_RAW_S.tlast : axis_crc.tlast; 


  assign AXIS_READY_RAW_S.tready  = !EOF ? axis_fifo.tstrb : 1'b0; 
  assign axis_ready_crc.tready  = !EOF ? 1'b0 : axis_ready_fifo.tready; 




  assign EOF = GENERIC_HEADER.valid && (noctects >= GENERIC_HEADER.orig_len);

  compute_fcs compute_fcs_i (
    .CLK(CLK),
    .RST_N(RST_N),
    .AXIS_RAW_S(AXIS_RAW_S),
    .AXIS_READY_RAW_S(), // Ignore, always accepting data
    .PREV_FCS(prev_fcs),
    .FCS(n_fcs)
  );

  fcs_fifo fcs_fifo_i (
    .s_aclk(CLK),                // input wire s_aclk
    .s_aresetn(RST_N),          // input wire s_aresetn
    .s_axis_tvalid(axis_fifo.tvalid),  // input wire s_axis_tvalid
    .s_axis_tready(axis_ready_fifo.tready),  // output wire s_axis_tready
    .s_axis_tdata(axis_fifo.tdata),    // input wire [127 : 0] s_axis_tdata
    .s_axis_tlast(axis_fifo.tlast),    // input wire s_axis_tlast
    .m_axis_tvalid(AXIS_RAW_CRC_M.tvalid),  // output wire m_axis_tvalid
    .m_axis_tready(AXIS_READY_RAW_CRC_M.tready),  // input wire m_axis_tready
    .m_axis_tdata(AXIS_RAW_CRC_M.tdata),    // output wire [127 : 0] m_axis_tdata
    .m_axis_tlast(AXIS_RAW_CRC_M.tlast)    // output wire m_axis_tlast
  );

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
  `AXI4_STREAM_STRUCT(128b) axis_pcap,      // Original PCAP
                           axis_pcap_lvl2, // PCAP without global header
                           axis_raw,       // RAW information of the PCAP file
                           axis_raw_crc,       // RAW information of the PCAP file with the correct CRC
                           axis_hwgen;     

  `AXI4_STREAM_READY_STRUCT(128b) axis_ready_pcap,      // Original PCAP
                           axis_ready_pcap_lvl2, // PCAP without global header
                           axis_ready_raw,       // RAW information of the PCAP file
                           axis_ready_raw_crc,       // RAW information of the PCAP file with the correct CRC
                           axis_ready_hwgen;     

  pcap_hdr_t    global_header;
  wire          global_header_valid;

  pcaprec_hdr_t local_header;
  wire          local_header_valid;

  genericrec_hdr_t gen_local_header;
  wire          eof;




  assign axis_pcap.tlast  = 1'b0;
  assign axis_pcap.tvalid = PCAP_TVALID;
  assign axis_pcap.tdata  = PCAP_TDATA;
  assign axis_pcap.tstrb  = 16'hFFFF;
  assign PCAP_TREADY      = axis_ready_pcap.tready;


  assign HWGEN_TDATA  = 128'h0;
  assign HWGEN_TVALID = 1'h0;

  assign axis_ready_raw_crc.tready = 1'b1;


  pcap_gheader_parser pcap_gheader_parser_i (
    .CLK(CLK),
    .RST_N(RST_N),
    .AXIS_PCAP_S(axis_pcap),
    .AXIS_READY_PCAP_S(axis_ready_pcap),
    .AXIS_RAW_M(axis_pcap_lvl2),
    .AXIS_READY_RAW_M(axis_ready_pcap_lvl2),
    .GLOBAL_HEADER(global_header),
    .GLOBAL_HEADER_VALID(global_header_valid)
  );

  pcap_lheader_parser pcap_lheader_parser_i (
    .CLK(CLK),
    .RST_N(RST_N || !eof),
    .AXIS_PCAP_S(axis_pcap_lvl2),
    .AXIS_READY_PCAP_S(axis_ready_pcap_lvl2),
    .AXIS_RAW_M(axis_raw),
    .AXIS_READY_RAW_M(axis_ready_raw),
    .LOCAL_HEADER(local_header),
    .LOCAL_HEADER_VALID(local_header_valid)
  );

  header2generic header2generic_i ( // Parse global and local headers in order to get a common structure.
    .CLK(CLK),
    .RST_N(RST_N),
    .GLOBAL_HEADER(global_header),
    .GLOBAL_HEADER_VALID(global_header_valid),    
    .LOCAL_HEADER(local_header),
    .LOCAL_HEADER_VALID(local_header_valid),
    .GENERIC_HEADER(gen_local_header),
    .INVALID_FORMAT()
  );

  packet_parser packet_parser_i (
    .CLK(CLK),
    .RST_N(RST_N),    
    .AXIS_RAW_S(axis_raw),
    .AXIS_READY_RAW_S(axis_ready_raw),
    .AXIS_RAW_CRC_M(axis_raw_crc),
    .AXIS_READY_RAW_CRC_M(axis_ready_raw_crc),
    .GENERIC_HEADER(gen_local_header),
    .EOF(eof)
  );

  hwgen_header_creator hwgen_header_creator_i (
    .CLK(CLK),
    .RST_N(RST_N),    
    .GENERIC_HEADER(gen_local_header),
    .EOF(eof),
    .HWGEN_HEADER(),
    .HWGEN_HEADER_VALID()
  );


endmodule