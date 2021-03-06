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
      GLOBAL_HEADER        <= '{default:0};
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
  input   wire                     NEXT_EOF,
  input   wire                     EOF,

  input   `AXI4_STREAM_STRUCT(128b) AXIS_PCAP_S,
  output   `AXI4_STREAM_READY_STRUCT(128b) AXIS_READY_PCAP_S,
  output  `AXI4_STREAM_STRUCT(128b) AXIS_RAW_M,
  input  `AXI4_STREAM_READY_STRUCT(128b) AXIS_READY_RAW_M,

  output   pcaprec_hdr_t            LOCAL_HEADER,
  output   wire                     LOCAL_HEADER_VALID
);

  typedef enum logic[1:0] {INITIAL_HDR, PARTIAL_HDR, END} lheader_parser_state_t;
  lheader_parser_state_t lheader_parser_state;

  logic is_lheader_valid, update_cnt,eop;
  logic [31:0] prev_packet_size;
  logic [31:0] noctects;
  logic [3:0]  offset_bus;
  
  assign is_lheader_valid = lheader_parser_state == END;

  always_ff @(negedge RST_N or posedge CLK) begin
    if(!RST_N) begin
      noctects   <= 32'h8;
      update_cnt<= 1'b1;
    end else begin
      if(!LOCAL_HEADER_VALID) begin
        update_cnt <= 1'b1;
        noctects   <= 16-offset_bus;
      end else if(AXIS_PCAP_S.tvalid & AXIS_READY_PCAP_S.tready & update_cnt) begin
        update_cnt <= 1'b1;
        noctects <= noctects + 16;
      end 
    end
  end

  assign eop = LOCAL_HEADER_VALID & AXIS_PCAP_S.tvalid & AXIS_READY_PCAP_S.tready & (noctects >= (prev_packet_size + `sizeof(pcaprec_hdr_t) -32));

  // We store the previous packet size so the offset can be computed.
  always_ff @(negedge RST_N or posedge CLK) begin
    if(!RST_N) begin
      prev_packet_size     <= 32'h0;
    end else begin
      if(LOCAL_HEADER_VALID) begin
        prev_packet_size <= LOCAL_HEADER.incl_len;
      end else begin
        prev_packet_size <= 32'hffffffff;//prev_packet_size;
      end
    end
  end
  // The global header is 128 b + 64 b long. The initial offset is (128b+64b) % 128b = 64b = 8B. 
  always_ff @(negedge RST_N or posedge CLK) begin
    if(!RST_N) begin
      offset_bus     <= 4'h8;
    end else begin
      if(eop) begin
        offset_bus <= offset_bus+prev_packet_size;
      end else begin
        offset_bus <= offset_bus;
      end
    end
  end

  always_ff @(negedge RST_N or posedge CLK) begin
    if(!RST_N) begin
      lheader_parser_state <= INITIAL_HDR;
      LOCAL_HEADER         <= '{default:0};
    end else begin
      if(eop) begin
        if(AXIS_PCAP_S.tvalid) begin
          case(offset_bus+prev_packet_size[3:0]) 
            4'h0: begin
              lheader_parser_state  <= END;
              LOCAL_HEADER.ts_sec   <= AXIS_PCAP_S.tdata[31:0]; 
              LOCAL_HEADER.ts_usec  <= AXIS_PCAP_S.tdata[63:32]; 
              LOCAL_HEADER.incl_len <= AXIS_PCAP_S.tdata[95:64]; 
              LOCAL_HEADER.orig_len <= AXIS_PCAP_S.tdata[127:96];
            end 
            4'h1: begin
              lheader_parser_state       <= PARTIAL_HDR;
              LOCAL_HEADER.ts_sec        <= AXIS_PCAP_S.tdata[39:8]; 
              LOCAL_HEADER.ts_usec       <= AXIS_PCAP_S.tdata[71:40]; 
              LOCAL_HEADER.incl_len      <= AXIS_PCAP_S.tdata[103:72]; 
              LOCAL_HEADER.orig_len[23:0]<= AXIS_PCAP_S.tdata[127:104];
            end
            4'h2: begin
              lheader_parser_state       <= PARTIAL_HDR;
              LOCAL_HEADER.ts_sec        <= AXIS_PCAP_S.tdata[47:16]; 
              LOCAL_HEADER.ts_usec       <= AXIS_PCAP_S.tdata[79:48]; 
              LOCAL_HEADER.incl_len      <= AXIS_PCAP_S.tdata[111:80]; 
              LOCAL_HEADER.orig_len[15:0]<= AXIS_PCAP_S.tdata[127:112]; 
            end
            4'h3: begin
              lheader_parser_state       <= PARTIAL_HDR;
              LOCAL_HEADER.ts_sec        <= AXIS_PCAP_S.tdata[55:24]; 
              LOCAL_HEADER.ts_usec       <= AXIS_PCAP_S.tdata[87:56]; 
              LOCAL_HEADER.incl_len      <= AXIS_PCAP_S.tdata[119:88]; 
              LOCAL_HEADER.orig_len[7:0] <= AXIS_PCAP_S.tdata[127:120]; 
            end
            4'h4: begin
              lheader_parser_state       <= PARTIAL_HDR;
              LOCAL_HEADER.ts_sec        <= AXIS_PCAP_S.tdata[63:32]; 
              LOCAL_HEADER.ts_usec       <= AXIS_PCAP_S.tdata[95:64];
              LOCAL_HEADER.incl_len      <= AXIS_PCAP_S.tdata[127:96]; 
            end
            4'h5: begin
              lheader_parser_state       <= PARTIAL_HDR;
              LOCAL_HEADER.ts_sec        <= AXIS_PCAP_S.tdata[71:40]; 
              LOCAL_HEADER.ts_usec       <= AXIS_PCAP_S.tdata[103:72];
              LOCAL_HEADER.incl_len[23:0]<= AXIS_PCAP_S.tdata[127:104]; 
            end
            4'h6: begin
              lheader_parser_state       <= PARTIAL_HDR;
              LOCAL_HEADER.ts_sec        <= AXIS_PCAP_S.tdata[79:48]; 
              LOCAL_HEADER.ts_usec       <= AXIS_PCAP_S.tdata[111:80];
              LOCAL_HEADER.incl_len[15:0]<= AXIS_PCAP_S.tdata[127:112];  
            end
            4'h7: begin
              lheader_parser_state       <= PARTIAL_HDR;
              LOCAL_HEADER.ts_sec        <= AXIS_PCAP_S.tdata[87:56]; 
              LOCAL_HEADER.ts_usec       <= AXIS_PCAP_S.tdata[119:88];
              LOCAL_HEADER.incl_len[7:0] <= AXIS_PCAP_S.tdata[127:120];  
            end
            4'h8: begin
              lheader_parser_state       <= PARTIAL_HDR;
              LOCAL_HEADER.ts_sec        <= AXIS_PCAP_S.tdata[95:64]; 
              LOCAL_HEADER.ts_usec       <= AXIS_PCAP_S.tdata[127:96]; 
            end
            4'h9: begin
              lheader_parser_state       <= PARTIAL_HDR;
              LOCAL_HEADER.ts_sec        <= AXIS_PCAP_S.tdata[103:72]; 
              LOCAL_HEADER.ts_usec[23:0] <= AXIS_PCAP_S.tdata[127:104]; 
            end
            4'ha: begin
              lheader_parser_state       <= PARTIAL_HDR;
              LOCAL_HEADER.ts_sec        <= AXIS_PCAP_S.tdata[111:80]; 
              LOCAL_HEADER.ts_usec[15:0] <= AXIS_PCAP_S.tdata[127:112]; 
            end
            4'hb: begin
              lheader_parser_state       <= PARTIAL_HDR;
              LOCAL_HEADER.ts_sec        <= AXIS_PCAP_S.tdata[119:88]; 
              LOCAL_HEADER.ts_usec[7:0] <= AXIS_PCAP_S.tdata[127:120]; 
            end
            4'hc: begin
              lheader_parser_state       <= PARTIAL_HDR;
              LOCAL_HEADER.ts_sec        <= AXIS_PCAP_S.tdata[127:96]; 
            end
            4'hd: begin
              lheader_parser_state       <= PARTIAL_HDR;
              LOCAL_HEADER.ts_sec[23:0]  <= AXIS_PCAP_S.tdata[127:104]; 
            end
            4'he: begin
              lheader_parser_state       <= PARTIAL_HDR;
              LOCAL_HEADER.ts_sec[15:0]  <= AXIS_PCAP_S.tdata[127:112]; 
            end
            4'hf: begin
              lheader_parser_state       <= PARTIAL_HDR;
              LOCAL_HEADER.ts_sec[7:0]   <= AXIS_PCAP_S.tdata[127:120]; 
            end
            default: begin
            end
          endcase
        end else begin
          LOCAL_HEADER           <= '{default:0};
          lheader_parser_state   <= INITIAL_HDR;
        end
      end else begin
        case(lheader_parser_state)
          INITIAL_HDR: begin
            if(AXIS_PCAP_S.tvalid) begin
              case(offset_bus) 
                4'h0: begin
                  lheader_parser_state  <= END;
                  LOCAL_HEADER.ts_sec   <= AXIS_PCAP_S.tdata[31:0]; 
                  LOCAL_HEADER.ts_usec  <= AXIS_PCAP_S.tdata[63:32]; 
                  LOCAL_HEADER.incl_len <= AXIS_PCAP_S.tdata[95:64]; 
                  LOCAL_HEADER.orig_len <= AXIS_PCAP_S.tdata[127:96];
                end 
                4'h1: begin
                  lheader_parser_state       <= PARTIAL_HDR;
                  LOCAL_HEADER.ts_sec        <= AXIS_PCAP_S.tdata[39:8]; 
                  LOCAL_HEADER.ts_usec       <= AXIS_PCAP_S.tdata[71:40]; 
                  LOCAL_HEADER.incl_len      <= AXIS_PCAP_S.tdata[103:72]; 
                  LOCAL_HEADER.orig_len[23:0]<= AXIS_PCAP_S.tdata[127:104];
                end
                4'h2: begin
                  lheader_parser_state       <= PARTIAL_HDR;
                  LOCAL_HEADER.ts_sec        <= AXIS_PCAP_S.tdata[47:16]; 
                  LOCAL_HEADER.ts_usec       <= AXIS_PCAP_S.tdata[79:48]; 
                  LOCAL_HEADER.incl_len      <= AXIS_PCAP_S.tdata[111:80]; 
                  LOCAL_HEADER.orig_len[15:0]<= AXIS_PCAP_S.tdata[127:112]; 
                end
                4'h3: begin
                  lheader_parser_state       <= PARTIAL_HDR;
                  LOCAL_HEADER.ts_sec        <= AXIS_PCAP_S.tdata[55:24]; 
                  LOCAL_HEADER.ts_usec       <= AXIS_PCAP_S.tdata[87:56]; 
                  LOCAL_HEADER.incl_len      <= AXIS_PCAP_S.tdata[119:88]; 
                  LOCAL_HEADER.orig_len[7:0] <= AXIS_PCAP_S.tdata[127:120]; 
                end
                4'h4: begin
                  lheader_parser_state       <= PARTIAL_HDR;
                  LOCAL_HEADER.ts_sec        <= AXIS_PCAP_S.tdata[63:32]; 
                  LOCAL_HEADER.ts_usec       <= AXIS_PCAP_S.tdata[95:64];
                  LOCAL_HEADER.incl_len      <= AXIS_PCAP_S.tdata[127:96]; 
                end
                4'h5: begin
                  lheader_parser_state       <= PARTIAL_HDR;
                  LOCAL_HEADER.ts_sec        <= AXIS_PCAP_S.tdata[71:40]; 
                  LOCAL_HEADER.ts_usec       <= AXIS_PCAP_S.tdata[103:72];
                  LOCAL_HEADER.incl_len[23:0]<= AXIS_PCAP_S.tdata[127:104]; 
                end
                4'h6: begin
                  lheader_parser_state       <= PARTIAL_HDR;
                  LOCAL_HEADER.ts_sec        <= AXIS_PCAP_S.tdata[79:48]; 
                  LOCAL_HEADER.ts_usec       <= AXIS_PCAP_S.tdata[111:80];
                  LOCAL_HEADER.incl_len[15:0]<= AXIS_PCAP_S.tdata[127:112];  
                end
                4'h7: begin
                  lheader_parser_state       <= PARTIAL_HDR;
                  LOCAL_HEADER.ts_sec        <= AXIS_PCAP_S.tdata[87:56]; 
                  LOCAL_HEADER.ts_usec       <= AXIS_PCAP_S.tdata[119:88];
                  LOCAL_HEADER.incl_len[7:0] <= AXIS_PCAP_S.tdata[127:120];  
                end
                4'h8: begin
                  lheader_parser_state       <= PARTIAL_HDR;
                  LOCAL_HEADER.ts_sec        <= AXIS_PCAP_S.tdata[95:64]; 
                  LOCAL_HEADER.ts_usec       <= AXIS_PCAP_S.tdata[127:96]; 
                end
                4'h9: begin
                  lheader_parser_state       <= PARTIAL_HDR;
                  LOCAL_HEADER.ts_sec        <= AXIS_PCAP_S.tdata[103:72]; 
                  LOCAL_HEADER.ts_usec[23:0] <= AXIS_PCAP_S.tdata[127:104]; 
                end
                4'ha: begin
                  lheader_parser_state       <= PARTIAL_HDR;
                  LOCAL_HEADER.ts_sec        <= AXIS_PCAP_S.tdata[111:80]; 
                  LOCAL_HEADER.ts_usec[15:0] <= AXIS_PCAP_S.tdata[127:112]; 
                end
                4'hb: begin
                  lheader_parser_state       <= PARTIAL_HDR;
                  LOCAL_HEADER.ts_sec        <= AXIS_PCAP_S.tdata[119:88]; 
                  LOCAL_HEADER.ts_usec[7:0] <= AXIS_PCAP_S.tdata[127:120]; 
                end
                4'hc: begin
                  lheader_parser_state       <= PARTIAL_HDR;
                  LOCAL_HEADER.ts_sec        <= AXIS_PCAP_S.tdata[127:96]; 
                end
                4'hd: begin
                  lheader_parser_state       <= PARTIAL_HDR;
                  LOCAL_HEADER.ts_sec[23:0]  <= AXIS_PCAP_S.tdata[127:104]; 
                end
                4'he: begin
                  lheader_parser_state       <= PARTIAL_HDR;
                  LOCAL_HEADER.ts_sec[15:0]  <= AXIS_PCAP_S.tdata[127:112]; 
                end
                4'hf: begin
                  lheader_parser_state       <= PARTIAL_HDR;
                  LOCAL_HEADER.ts_sec[7:0]   <= AXIS_PCAP_S.tdata[127:120]; 
                end
                default: begin
                end
              endcase
            end else begin 
              lheader_parser_state <= lheader_parser_state;
            end
          end
          PARTIAL_HDR: begin
            if(AXIS_PCAP_S.tvalid) begin
              case(offset_bus) 
                4'h1: begin
                  lheader_parser_state         <= END;
                  LOCAL_HEADER.orig_len[31:24] <= AXIS_PCAP_S.tdata[7:0]; 
                end
                4'h2: begin
                  lheader_parser_state         <= END;
                  LOCAL_HEADER.orig_len[31:16] <= AXIS_PCAP_S.tdata[15:0]; 
                end
                4'h3: begin
                  lheader_parser_state         <= END;
                  LOCAL_HEADER.orig_len[31:8]  <= AXIS_PCAP_S.tdata[23:0];  
                end
                4'h4: begin
                  lheader_parser_state         <= END;
                  LOCAL_HEADER.orig_len        <= AXIS_PCAP_S.tdata[31:0]; 
                end
                4'h5: begin
                  lheader_parser_state         <= END;
                  LOCAL_HEADER.incl_len[31:24] <= AXIS_PCAP_S.tdata[7:0]; 
                  LOCAL_HEADER.orig_len        <= AXIS_PCAP_S.tdata[39:8];
                end
                4'h6: begin
                  lheader_parser_state         <= END;
                  LOCAL_HEADER.incl_len[31:16] <= AXIS_PCAP_S.tdata[15:0]; 
                  LOCAL_HEADER.orig_len        <= AXIS_PCAP_S.tdata[47:16]; 
                end
                4'h7: begin
                  lheader_parser_state         <= END;
                  LOCAL_HEADER.incl_len[31:8]  <= AXIS_PCAP_S.tdata[23:0]; 
                  LOCAL_HEADER.orig_len        <= AXIS_PCAP_S.tdata[55:24]; 
                end
                4'h8: begin
                  lheader_parser_state         <= END;
                  LOCAL_HEADER.incl_len        <= AXIS_PCAP_S.tdata[31:0]; 
                  LOCAL_HEADER.orig_len        <= AXIS_PCAP_S.tdata[63:32];
                end
                4'h9: begin
                  lheader_parser_state         <= END;
                  LOCAL_HEADER.ts_usec[31:24]  <= AXIS_PCAP_S.tdata[7:0]; 
                  LOCAL_HEADER.incl_len        <= AXIS_PCAP_S.tdata[39:8]; 
                  LOCAL_HEADER.orig_len        <= AXIS_PCAP_S.tdata[63:40]; 
                end
                4'ha: begin
                  lheader_parser_state         <= END;
                  LOCAL_HEADER.ts_usec[31:16]  <= AXIS_PCAP_S.tdata[15:0]; 
                  LOCAL_HEADER.incl_len        <= AXIS_PCAP_S.tdata[47:16]; 
                  LOCAL_HEADER.orig_len        <= AXIS_PCAP_S.tdata[63:48]; 
                end
                4'hb: begin
                  lheader_parser_state         <= END;
                  LOCAL_HEADER.ts_usec[31:8]   <= AXIS_PCAP_S.tdata[23:0]; 
                  LOCAL_HEADER.incl_len        <= AXIS_PCAP_S.tdata[55:24]; 
                  LOCAL_HEADER.orig_len        <= AXIS_PCAP_S.tdata[87:56];  
                end
                4'hc: begin
                  lheader_parser_state         <= END;
                  LOCAL_HEADER.ts_usec         <= AXIS_PCAP_S.tdata[31:0]; 
                  LOCAL_HEADER.incl_len        <= AXIS_PCAP_S.tdata[63:32]; 
                  LOCAL_HEADER.orig_len        <= AXIS_PCAP_S.tdata[95:64]; 
                end
                4'hd: begin
                  lheader_parser_state         <= END;
                  LOCAL_HEADER.ts_sec[31:24]   <= AXIS_PCAP_S.tdata[7:0]; 
                  LOCAL_HEADER.ts_usec         <= AXIS_PCAP_S.tdata[39:8]; 
                  LOCAL_HEADER.incl_len        <= AXIS_PCAP_S.tdata[71:40]; 
                  LOCAL_HEADER.orig_len        <= AXIS_PCAP_S.tdata[95:72]; 
                end
                4'he: begin
                  lheader_parser_state         <= END;
                  LOCAL_HEADER.ts_sec[31:16]   <= AXIS_PCAP_S.tdata[15:0]; 
                  LOCAL_HEADER.ts_usec         <= AXIS_PCAP_S.tdata[47:16]; 
                  LOCAL_HEADER.incl_len        <= AXIS_PCAP_S.tdata[79:48]; 
                  LOCAL_HEADER.orig_len        <= AXIS_PCAP_S.tdata[112:80]; 
                end
                4'hf: begin
                  lheader_parser_state         <= END;
                  LOCAL_HEADER.ts_sec[31:8]    <= AXIS_PCAP_S.tdata[23:0]; 
                  LOCAL_HEADER.ts_usec         <= AXIS_PCAP_S.tdata[55:24]; 
                  LOCAL_HEADER.incl_len        <= AXIS_PCAP_S.tdata[87:56]; 
                  LOCAL_HEADER.orig_len        <= AXIS_PCAP_S.tdata[119:88]; 
                end
                default: begin
                end
              endcase
            end else begin 
              lheader_parser_state <= lheader_parser_state;
            end            
          end

          END: begin // Preserve the state until next packet.
          end
          default: begin
            lheader_parser_state <= INITIAL_HDR;
          end
        endcase
      end
    end
  end  


  always_ff @(negedge RST_N or posedge CLK) begin
    if(!RST_N) begin
      AXIS_RAW_M.tdata   <= 128'b0;
      AXIS_RAW_M.tvalid  <= 1'b0;
      AXIS_RAW_M.tstrb  <= 16'b0;
    end else begin
      AXIS_RAW_M.tdata   <= AXIS_PCAP_S.tdata;
      AXIS_RAW_M.tvalid  <= (lheader_parser_state == END || (AXIS_PCAP_S.tvalid & lheader_parser_state == PARTIAL_HDR));
      if(lheader_parser_state == END) begin
        AXIS_RAW_M.tstrb   <= 16'hFFFF;
      end else if(lheader_parser_state == PARTIAL_HDR) begin 
        case(offset_bus)
          4'h1: begin
            AXIS_RAW_M.tstrb <= 16'hFFFE;
          end
          4'h2: begin
            AXIS_RAW_M.tstrb <= 16'hFFFC;
          end
          4'h3: begin
            AXIS_RAW_M.tstrb <= 16'hFFF8;
          end
          4'h4: begin
            AXIS_RAW_M.tstrb <= 16'hFFF0;
          end
          4'h5: begin
            AXIS_RAW_M.tstrb <= 16'hFFE0;
          end
          4'h6: begin
            AXIS_RAW_M.tstrb <= 16'hFFC0;
          end
          4'h7: begin
            AXIS_RAW_M.tstrb <= 16'hFF80;
          end
          4'h8: begin
            AXIS_RAW_M.tstrb <= 16'hFF00;
          end
          4'h9: begin
            AXIS_RAW_M.tstrb <= 16'hFE00;
          end
          4'ha: begin
            AXIS_RAW_M.tstrb <= 16'hFC00;
          end
          4'hb: begin
            AXIS_RAW_M.tstrb <= 16'hF800;
          end
          4'hc: begin
            AXIS_RAW_M.tstrb <= 16'hF000;
          end
          4'hd: begin
            AXIS_RAW_M.tstrb <= 16'hE000;
          end
          4'he: begin
            AXIS_RAW_M.tstrb <= 16'hC000;
          end
          4'hf: begin
            AXIS_RAW_M.tstrb <= 16'h8000;
          end
          default: begin
            AXIS_RAW_M.tstrb <= 16'h0000;
          end
        endcase
      end else begin
        AXIS_RAW_M.tstrb   <= 16'h0;
      end
    end
  end
  //assign AXIS_RAW_M.tdata   = AXIS_PCAP_S.tdata;
  //assign AXIS_RAW_M.tvalid  = (lheader_parser_state == END || (AXIS_PCAP_S.tvalid & lheader_parser_state == PARTIAL_HDR));
//  assign AXIS_RAW_M.tstrb   = lheader_parser_state == 2'h2 ? 16'hFFFF : 16'hFF00;


  assign AXIS_READY_PCAP_S.tready = is_lheader_valid ? 
                                      AXIS_READY_RAW_M.tready
                                      : 1'b1;
  assign LOCAL_HEADER_VALID = is_lheader_valid;
endmodule


module compute_fcs ( 
  input   wire                     CLK,
  input   wire                     RST_N,

  input   `AXI4_STREAM_STRUCT(128b)       AXIS_RAW_S,
  output  `AXI4_STREAM_READY_STRUCT(128b) AXIS_READY_RAW_S,

  output  logic [31:0]             FCS

);

  wire [15:0] strobe;
  assign AXIS_READY_RAW_S.tready = 1'b1;


  wire s_fcs_crc_calc_en;
  wire s_crc_valid;
  wire [31:0] s_crc_reg;

  // if it is the last packet remove the strobe associate to the FCS in the computation
  //assign strobe = AXIS_RAW_S.tlast ? {4'h0, AXIS_RAW_S.tstrb[15:4]} : AXIS_RAW_S.tstrb; 


  axis_eth_fcs axis_eth_fcs_i (
    .clk(CLK),
    .rst(!RST_N),
    .input_axis_tdata(AXIS_RAW_S.tdata),
    .input_axis_tstrb(AXIS_RAW_S.tstrb),
    .input_axis_tvalid(AXIS_RAW_S.tvalid),
    .input_axis_tready(),
    .input_axis_tlast(AXIS_RAW_S.tlast),
    .output_fcs(FCS),
    .output_fcs_valid()
  );

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
                              LOCAL_HEADER.ts_sec*1000000000 + LOCAL_HEADER.ts_usec 
                              : LOCAL_HEADER.ts_sec*1000000000 + LOCAL_HEADER.ts_usec*1000;
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
        HWGEN_HEADER.ifg      <= ((GENERIC_HEADER.ts-prev_ts)*NS_PER_CYCLE_INV_x1e5)/100000;
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
  output  `AXI4_STREAM_READY_STRUCT(128b) AXIS_READY_RAW_S,

  output  `AXI4_STREAM_STRUCT(128b) AXIS_RAW_CRC_M,
  input   `AXI4_STREAM_READY_STRUCT(128b) AXIS_READY_RAW_CRC_M,

  input   genericrec_hdr_t          GENERIC_HEADER,
  output  wire                      NEXT_EOF,
  output  reg                       EOF
);



  logic [31:0] n_fcs;
  logic [31:0] noctects;
  logic [3:0]  offset_bus;
  logic [3:0]  offset_bus_plus_len;
  logic [127:0]  axis_raw_s_tdata_pipe;
  logic [127:0]  axis_raw_s_tvalid_pipe;
  logic [15:0]  axis_raw_s_tlast_tstrb;
  logic [31:0] prev_packet_size;

  `AXI4_STREAM_STRUCT(128b) axis_fifo;
  `AXI4_STREAM_STRUCT(128b) axis_fcs;
  `AXI4_STREAM_READY_STRUCT(128b) axis_ready_fifo;
  logic update_cnt;



  typedef enum logic[2:0] {INI, DATA, WAIT_CRC, END, CRC, IDLE} dump_state_t;
  dump_state_t dump_state,dump_state_pipe;


  always_ff @(negedge RST_N or posedge CLK) begin
    if(!RST_N) begin
      noctects   <= 32'h0;
      update_cnt<= 1'b1;
    end else begin
      if(NEXT_EOF) begin
        update_cnt <= 1'b0;
      end else if(dump_state == CRC) begin
        if(AXIS_RAW_S.tvalid & AXIS_READY_RAW_S.tready) begin
          noctects <= AXIS_RAW_S.tstrb [0] + AXIS_RAW_S.tstrb [1] + AXIS_RAW_S.tstrb [2]
                      + AXIS_RAW_S.tstrb [3] + AXIS_RAW_S.tstrb [4] + AXIS_RAW_S.tstrb [5]
                      + AXIS_RAW_S.tstrb [6] + AXIS_RAW_S.tstrb [7] + AXIS_RAW_S.tstrb [8]
                      + AXIS_RAW_S.tstrb [9] + AXIS_RAW_S.tstrb [10] + AXIS_RAW_S.tstrb [11]
                      + AXIS_RAW_S.tstrb [12] + AXIS_RAW_S.tstrb [13] + AXIS_RAW_S.tstrb [14]
                      + AXIS_RAW_S.tstrb [15];
        end else begin
          noctects <= 32'h0;
        end
        update_cnt <= 1'b1;
      end else if(AXIS_RAW_S.tvalid & AXIS_READY_RAW_S.tready & update_cnt) begin
        update_cnt <= 1'b1;
        noctects <= noctects + AXIS_RAW_S.tstrb [0] + AXIS_RAW_S.tstrb [1] + AXIS_RAW_S.tstrb [2]
                    + AXIS_RAW_S.tstrb [3] + AXIS_RAW_S.tstrb [4] + AXIS_RAW_S.tstrb [5]
                    + AXIS_RAW_S.tstrb [6] + AXIS_RAW_S.tstrb [7] + AXIS_RAW_S.tstrb [8]
                    + AXIS_RAW_S.tstrb [9] + AXIS_RAW_S.tstrb [10] + AXIS_RAW_S.tstrb [11]
                    + AXIS_RAW_S.tstrb [12] + AXIS_RAW_S.tstrb [13] + AXIS_RAW_S.tstrb [14]
                    + AXIS_RAW_S.tstrb [15];
      end 

    end
  end



  always_ff @(negedge RST_N or posedge CLK) begin
    if(!RST_N) begin
      dump_state <= IDLE;
    end else begin
      if(!NEXT_EOF) begin // Process more data
        if(AXIS_RAW_S.tvalid & AXIS_READY_RAW_S.tready) begin
          if(dump_state==IDLE) begin
            dump_state <= DATA; //INI;
          end else begin
            dump_state <= DATA;
          end
        end else begin
          if(dump_state==WAIT_CRC) begin
            dump_state <= END;
          end else if(dump_state==END) begin
            dump_state <= CRC;
          end else if(dump_state==CRC) begin
            dump_state <= IDLE;
          end else begin
            dump_state <= dump_state;
          end
        end
      end else begin 
        dump_state <= WAIT_CRC;
      end
    end
  end

  always_ff @(negedge RST_N or posedge CLK) begin
    if(!RST_N) begin
      offset_bus <= 4'h8;
    end else begin
      if(dump_state == DATA && EOF) begin
        offset_bus <= offset_bus_plus_len;
      end else if(dump_state == CRC || (offset_bus!=0 && dump_state == END)) begin
        offset_bus <= offset_bus_plus_len + `sizeof(pcaprec_hdr_t);
      end else begin
        offset_bus <= offset_bus;
      end
    end
  end

  // Register the offset plus the length just in case that the Header is modified within the next cycle
  always_ff @(negedge RST_N or posedge CLK) begin
    if(!RST_N) begin
      offset_bus_plus_len <= 4'h0;
      dump_state_pipe     <= IDLE;
      prev_packet_size     <= 32'hffffffff;
    end else begin
      dump_state_pipe <= dump_state;
      if(dump_state == DATA && dump_state_pipe != dump_state) begin // Just the first time we update the value.
        offset_bus_plus_len <= offset_bus + (GENERIC_HEADER.orig_len);
        prev_packet_size    <=  GENERIC_HEADER.orig_len;
      end else if(dump_state == CRC) begin
        prev_packet_size  <= 32'hffffffff;
      end
    end
  end

  assign AXIS_READY_RAW_S.tready  = dump_state != CRC && dump_state != END && dump_state != WAIT_CRC; 
  assign NEXT_EOF = AXIS_RAW_S.tvalid & AXIS_READY_RAW_S.tready & (noctects+16 >= prev_packet_size);

  always_ff @(negedge RST_N or posedge CLK) begin
    if(!RST_N) begin
      EOF<= 1'b0;
    end else begin
      if(AXIS_RAW_S.tvalid) begin
        EOF <= NEXT_EOF;
      end 
    end
  end

  assign axis_raw_s_tlast_tstrb = (offset_bus_plus_len) == 4'h0 ? 16'hFFFF :
                                (offset_bus_plus_len) == 4'h1 ? 16'hFFFF :
                                (offset_bus_plus_len) == 4'h2 ? 16'hFFFF :
                                (offset_bus_plus_len) == 4'h3 ? 16'hFFFF :
                                (offset_bus_plus_len) == 4'h4 ? 16'hFFFF :
                                (offset_bus_plus_len) == 4'h5 ? 16'h7FFF :
                                (offset_bus_plus_len) == 4'h6 ? 16'h3FFF :
                                (offset_bus_plus_len) == 4'h7 ? 16'h1FFF :
                                (offset_bus_plus_len) == 4'h8 ? 16'h0FFF :
                                (offset_bus_plus_len) == 4'h9 ? 16'h07FF :
                                (offset_bus_plus_len) == 4'ha ? 16'h03FF :
                                (offset_bus_plus_len) == 4'hb ? 16'h01FF :
                                (offset_bus_plus_len) == 4'hc ? 16'h00FF :
                                (offset_bus_plus_len) == 4'hd ? 16'h007F :
                                (offset_bus_plus_len) == 4'he ? 16'h003F :
                                (offset_bus_plus_len) == 4'hf ? 16'h001F :
                                16'h0;


  assign axis_fcs.tdata = axis_fifo.tdata;
  assign axis_fcs.tstrb = dump_state == WAIT_CRC ? axis_raw_s_tlast_tstrb : axis_fifo.tstrb;
  assign axis_fcs.tlast = (axis_fifo.tvalid && dump_state == END) ||  (dump_state == WAIT_CRC);
  assign axis_fcs.tvalid = (axis_fifo.tvalid && dump_state != CRC) ||  (dump_state == WAIT_CRC); // Obtain CRC from the module. Disable valid signal
  // Compute fcs in any strb situation.
  compute_fcs compute_fcs_i (
    .CLK(CLK),
    .RST_N(RST_N),
    .AXIS_RAW_S(axis_fcs),
    .AXIS_READY_RAW_S(), // Ignore, always accepting data
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

  // Align the data to the 128 bits interface. Use an auxiliar register 
  always_ff @(negedge RST_N or posedge CLK) begin
    if(!RST_N) begin
      axis_raw_s_tvalid_pipe <= 1'b0;
      axis_raw_s_tdata_pipe  <= 128'h0;
    end else begin
      if(AXIS_RAW_S.tvalid & AXIS_READY_RAW_S.tready) begin
       // if( !NEXT_EOF ) begin
          case(offset_bus) 
            4'h0: begin
              axis_raw_s_tvalid_pipe      <= 1'b1;
              axis_raw_s_tdata_pipe       <= AXIS_RAW_S.tdata;
            end
            4'h1: begin
              axis_raw_s_tvalid_pipe       <= 1'b0;
              axis_raw_s_tdata_pipe[119:0] <= AXIS_RAW_S.tdata[127:8];
            end
            4'h2: begin
              axis_raw_s_tvalid_pipe       <= 1'b0;
              axis_raw_s_tdata_pipe[111:0] <= AXIS_RAW_S.tdata[127:16];
            end
            4'h3: begin
              axis_raw_s_tvalid_pipe       <= 1'b0;
              axis_raw_s_tdata_pipe[103:0] <= AXIS_RAW_S.tdata[127:24];
            end
            4'h4: begin
              axis_raw_s_tvalid_pipe       <= 1'b0;
              axis_raw_s_tdata_pipe[95:0] <= AXIS_RAW_S.tdata[127:32];
            end
            4'h5: begin
              axis_raw_s_tvalid_pipe       <= 1'b0;
              axis_raw_s_tdata_pipe[87:0] <= AXIS_RAW_S.tdata[127:40];
            end
            4'h6: begin
              axis_raw_s_tvalid_pipe       <= 1'b0;
              axis_raw_s_tdata_pipe[79:0] <= AXIS_RAW_S.tdata[127:48];
            end
            4'h7: begin
              axis_raw_s_tvalid_pipe       <= 1'b0;
              axis_raw_s_tdata_pipe[71:0] <= AXIS_RAW_S.tdata[127:56];
            end
            4'h8: begin
              axis_raw_s_tvalid_pipe       <= 1'b0;
              axis_raw_s_tdata_pipe[63:0] <= AXIS_RAW_S.tdata[127:64];
            end
            4'h9: begin
              axis_raw_s_tvalid_pipe       <= 1'b0;
              axis_raw_s_tdata_pipe[55:0] <= AXIS_RAW_S.tdata[127:72];
            end
            4'ha: begin
              axis_raw_s_tvalid_pipe       <= 1'b0;
              axis_raw_s_tdata_pipe[47:0] <= AXIS_RAW_S.tdata[127:80];
            end
            4'hb: begin
              axis_raw_s_tvalid_pipe       <= 1'b0;
              axis_raw_s_tdata_pipe[39:0] <= AXIS_RAW_S.tdata[127:88];
            end
            4'hc: begin
              axis_raw_s_tvalid_pipe       <= 1'b0;
              axis_raw_s_tdata_pipe[31:0] <= AXIS_RAW_S.tdata[127:96];
            end
            4'hd: begin
              axis_raw_s_tvalid_pipe       <= 1'b0;
              axis_raw_s_tdata_pipe[23:0] <= AXIS_RAW_S.tdata[127:104];
            end
            4'he: begin
              axis_raw_s_tvalid_pipe       <= 1'b0;
              axis_raw_s_tdata_pipe[15:0] <= AXIS_RAW_S.tdata[127:112];
            end
            4'hf: begin
              axis_raw_s_tvalid_pipe       <= 1'b0;
              axis_raw_s_tdata_pipe[7:0]   <= AXIS_RAW_S.tdata[127:120];
            end
            default: begin
              axis_raw_s_tvalid_pipe       <= 1'b0;
            end
          endcase
     /*   end else begin
          axis_raw_s_tdata_pipe       <= AXIS_RAW_S.tdata;
        end*/
      end 
    end
  end



  wire cycles_2;
  wire [127:0] data_src;
  assign cycles_2 = offset_bus_plus_len>offset_bus || AXIS_RAW_S.tstrb == 16'hffff;
  assign data_src = axis_fifo.tdata; //cycles_2 ? axis_raw_s_tdata_pipe : axis_fifo.tdata;
  always_ff @(negedge RST_N or posedge CLK) begin
    if(!RST_N) begin
      axis_fifo.tvalid <= 1'b0;
      axis_fifo.tdata  <= 128'b0;
      axis_fifo.tstrb  <= 16'b0;
      axis_fifo.tlast  <= 1'b0;
    end else begin
      case(dump_state)
        DATA: begin // Receive second and successive pieces of information. The pipe is full.
          case(offset_bus)
            4'h0: begin
              axis_fifo.tvalid <= !NEXT_EOF;
              axis_fifo.tdata  <= axis_raw_s_tdata_pipe;
              axis_fifo.tstrb  <= 16'hFFFF;
              axis_fifo.tlast  <= 1'b0;
            end
            4'h1: begin
              axis_fifo.tvalid <= !NEXT_EOF;
              axis_fifo.tdata  <= {AXIS_RAW_S.tdata[7:0], axis_raw_s_tdata_pipe[119:0]};
              axis_fifo.tstrb  <= 16'hFFFF;
              axis_fifo.tlast  <= 1'b0;
            end
            4'h2: begin
              axis_fifo.tvalid <= !NEXT_EOF;
              axis_fifo.tdata  <= {AXIS_RAW_S.tdata[15:0], axis_raw_s_tdata_pipe[111:0]};
              axis_fifo.tstrb  <= 16'hFFFF;
              axis_fifo.tlast  <= 1'b0;
            end
            4'h3: begin
              axis_fifo.tvalid <= !NEXT_EOF;
              axis_fifo.tdata  <= {AXIS_RAW_S.tdata[23:0], axis_raw_s_tdata_pipe[103:0]};
              axis_fifo.tstrb  <= 16'hFFFF;
              axis_fifo.tlast  <= 1'b0;
            end
            4'h4: begin
              axis_fifo.tvalid <= !NEXT_EOF;
              axis_fifo.tdata  <= {AXIS_RAW_S.tdata[31:0], axis_raw_s_tdata_pipe[95:0]};
              axis_fifo.tstrb  <= 16'hFFFF;
              axis_fifo.tlast  <= 1'b0;
            end
            4'h5: begin
              axis_fifo.tvalid <= !NEXT_EOF;
              axis_fifo.tdata  <= {AXIS_RAW_S.tdata[39:0], axis_raw_s_tdata_pipe[87:0]};
              axis_fifo.tstrb  <= 16'hFFFF;
              axis_fifo.tlast  <= 1'b0;
            end
            4'h6: begin
              axis_fifo.tvalid <= !NEXT_EOF;
              axis_fifo.tdata  <= {AXIS_RAW_S.tdata[47:0], axis_raw_s_tdata_pipe[79:0]};
              axis_fifo.tstrb  <= 16'hFFFF;
              axis_fifo.tlast  <= 1'b0;
            end
            4'h7: begin
              axis_fifo.tvalid <= !NEXT_EOF;
              axis_fifo.tdata  <= {AXIS_RAW_S.tdata[55:0], axis_raw_s_tdata_pipe[71:0]};
              axis_fifo.tstrb  <= 16'hFFFF;
              axis_fifo.tlast  <= 1'b0;
            end
            4'h8: begin
              axis_fifo.tvalid <= !NEXT_EOF;
              axis_fifo.tdata  <= {AXIS_RAW_S.tdata[63:0], axis_raw_s_tdata_pipe[63:0]};
              axis_fifo.tstrb  <= 16'hFFFF;
              axis_fifo.tlast  <= 1'b0;
            end
            4'h9: begin
              axis_fifo.tvalid <= !NEXT_EOF;
              axis_fifo.tdata  <= {AXIS_RAW_S.tdata[71:0], axis_raw_s_tdata_pipe[55:0]};
              axis_fifo.tstrb  <= 16'hFFFF;
              axis_fifo.tlast  <= 1'b0;
            end
            4'ha: begin
              axis_fifo.tvalid <= !NEXT_EOF;
              axis_fifo.tdata  <= {AXIS_RAW_S.tdata[79:0], axis_raw_s_tdata_pipe[47:0]};
              axis_fifo.tstrb  <= 16'hFFFF;
              axis_fifo.tlast  <= 1'b0;
            end
            4'hb: begin
              axis_fifo.tvalid <= !NEXT_EOF;
              axis_fifo.tdata  <= {AXIS_RAW_S.tdata[87:0], axis_raw_s_tdata_pipe[39:0]};
              axis_fifo.tstrb  <= 16'hFFFF;
              axis_fifo.tlast  <= 1'b0;
            end
            4'hc: begin
              axis_fifo.tvalid <= !NEXT_EOF;
              axis_fifo.tdata  <= {AXIS_RAW_S.tdata[95:0], axis_raw_s_tdata_pipe[31:0]};
              axis_fifo.tstrb  <= 16'hFFFF;
              axis_fifo.tlast  <= 1'b0;
            end
            4'hd: begin
              axis_fifo.tvalid <= !NEXT_EOF;
              axis_fifo.tdata  <= {AXIS_RAW_S.tdata[103:0], axis_raw_s_tdata_pipe[23:0]};
              axis_fifo.tstrb  <= 16'hFFFF;
              axis_fifo.tlast  <= 1'b0;
            end
            4'he: begin
              axis_fifo.tvalid <= !NEXT_EOF;
              axis_fifo.tdata  <= {AXIS_RAW_S.tdata[111:0], axis_raw_s_tdata_pipe[15:0]};
              axis_fifo.tstrb  <= 16'hFFFF;
              axis_fifo.tlast  <= 1'b0;
            end
            4'hf: begin
              axis_fifo.tvalid <= !NEXT_EOF;
              axis_fifo.tdata  <= {AXIS_RAW_S.tdata[119:0], axis_raw_s_tdata_pipe[7:0]};
              axis_fifo.tstrb  <= 16'hFFFF;
              axis_fifo.tlast  <= 1'b0;
            end
            default: begin
              axis_fifo.tvalid <= 1'b0;
              axis_fifo.tdata  <= 128'b0;
              axis_fifo.tstrb  <= 16'b0;
              axis_fifo.tlast  <= 1'b0;
            end
          endcase  
        end
        WAIT_CRC: begin
          if(cycles_2) begin
            axis_fifo.tvalid <= 1'b1;
            axis_fifo.tlast  <= 1'b0;
            axis_fifo.tdata  <= axis_fifo.tdata;
            axis_fifo.tstrb  <= 16'hffff;
          end else begin
            axis_fifo.tvalid <= 1'b0;
            axis_fifo.tlast  <= 1'b0;
            axis_fifo.tdata  <= axis_fifo.tdata;
            axis_fifo.tstrb  <= 16'b0;
          end
        end
        END: begin // An EOF has been received. The pipe is full, it has to be emptied.
            case(prev_packet_size[3:0])
              4'hf: begin
                axis_fifo.tvalid <= 1'b1;
                axis_fifo.tdata  <= data_src;
                axis_fifo.tstrb  <= 16'hFFFF;
                axis_fifo.tlast  <= 1'b0;
              end
              4'he: begin
                axis_fifo.tvalid <= 1'b1;
                axis_fifo.tdata  <= {n_fcs[7:0],data_src[119:0]};
                axis_fifo.tstrb  <= 16'hFFFF;
                axis_fifo.tlast  <= 1'b0;
              end
              4'hd: begin
                axis_fifo.tvalid <= 1'b1;
                axis_fifo.tdata  <= {n_fcs[15:0],data_src[111:0]};
                axis_fifo.tstrb  <= 16'hFFFF;
                axis_fifo.tlast  <= 1'b0;
              end
              4'hc: begin
                axis_fifo.tvalid <= 1'b1;
                axis_fifo.tdata  <= {n_fcs[23:0],data_src[103:0]};
                axis_fifo.tstrb  <= 16'hFFFF;
                axis_fifo.tlast  <= 1'b0;
              end
              4'hb: begin
                axis_fifo.tvalid <= 1'b1;
                axis_fifo.tdata  <= {n_fcs,data_src[95:0]};
                axis_fifo.tstrb  <= 16'hFFFF;
                axis_fifo.tlast  <= 1'b0;
              end
              4'ha: begin
                axis_fifo.tvalid <= 1'b1;
                axis_fifo.tdata  <= {{8{1'b0}},n_fcs,data_src[85:0]};
                axis_fifo.tstrb  <= 16'h7FFF;
                axis_fifo.tlast  <= 1'b1;
              end
              4'h9: begin
                axis_fifo.tvalid <= 1'b1;
                axis_fifo.tdata  <= {{16{1'b0}},n_fcs,data_src[79:0]};
                axis_fifo.tstrb  <= 16'h3FFF;
                axis_fifo.tlast  <= 1'b1;
              end
              4'h8: begin
                axis_fifo.tvalid <= 1'b1;
                axis_fifo.tdata  <= {{24{1'b0}},n_fcs,data_src[71:0]};
                axis_fifo.tstrb  <= 16'h1FFF;
                axis_fifo.tlast  <= 1'b1;
              end
              4'h7: begin
                axis_fifo.tvalid <= 1'b1;
                axis_fifo.tdata  <= {{32{1'b0}},n_fcs,data_src[63:0]};
                axis_fifo.tstrb  <= 16'h0FFF;
                axis_fifo.tlast  <= 1'b1;
              end
              4'h6: begin
                axis_fifo.tvalid <= 1'b1;
                axis_fifo.tdata  <= {{40{1'b0}},n_fcs,data_src[55:0]};
                axis_fifo.tstrb  <= 16'h07FF;
                axis_fifo.tlast  <= 1'b1;
              end
              4'h5: begin
                axis_fifo.tvalid <= 1'b1;
                axis_fifo.tdata  <= {{48{1'b0}},n_fcs,data_src[47:0]};
                axis_fifo.tstrb  <= 16'h03FF;
                axis_fifo.tlast  <= 1'b1;
              end
              4'h4: begin
                axis_fifo.tvalid <= 1'b1;
                axis_fifo.tdata  <= {{56{1'b0}},n_fcs,data_src[39:0]};
                axis_fifo.tstrb  <= 16'h01FF;
                axis_fifo.tlast  <= 1'b1;
              end
              4'h3: begin
                axis_fifo.tvalid <= 1'b1;
                axis_fifo.tdata  <= {{64{1'b0}},n_fcs,data_src[31:0]};
                axis_fifo.tstrb  <= 16'h00FF;
                axis_fifo.tlast  <= 1'b1;
              end
              4'h2: begin
                axis_fifo.tvalid <= 1'b1;
                axis_fifo.tdata  <= {{72{1'b0}},n_fcs,data_src[23:0]};
                axis_fifo.tstrb  <= 16'h007F;
                axis_fifo.tlast  <= 1'b1;
              end
              4'h1: begin
                axis_fifo.tvalid <= 1'b1;
                axis_fifo.tdata  <= {{80{1'b0}},n_fcs,data_src[15:0]};
                axis_fifo.tstrb  <= 16'h003F;
                axis_fifo.tlast  <= 1'b1;
              end
              4'h0: begin
                axis_fifo.tvalid <= 1'b1;
                axis_fifo.tdata  <= {{88{1'b0}},n_fcs,data_src[7:0]};
                axis_fifo.tstrb  <= 16'h001F;
                axis_fifo.tlast  <= 1'b1;
              end
              default: begin
                axis_fifo.tvalid <= 1'b0;
                axis_fifo.tdata  <= 128'b0;
                axis_fifo.tstrb  <= 16'b0;
                axis_fifo.tlast  <= 1'b0;
              end
            endcase 
        end
        CRC: begin
          case(prev_packet_size[3:0])
            4'hf: begin
              axis_fifo.tvalid <= 1'b1;
              axis_fifo.tdata  <= {{96{1'b0}},n_fcs};
              axis_fifo.tstrb  <= 16'h000F;
              axis_fifo.tlast  <= 1'b1;
            end
            4'he: begin
              axis_fifo.tvalid <= 1'b1;
              axis_fifo.tdata  <= {{104{1'b0}},n_fcs[31:8]};
              axis_fifo.tstrb  <= 16'h0003;
              axis_fifo.tlast  <= 1'b1;
            end
            4'hd: begin
              axis_fifo.tvalid <= 1'b1;
              axis_fifo.tdata  <= {{112{1'b0}},n_fcs[31:16]};
              axis_fifo.tstrb  <= 16'h0001;
              axis_fifo.tlast  <= 1'b1;
            end
            4'hc: begin
              axis_fifo.tvalid <= 1'b1;
              axis_fifo.tdata  <= {{120{1'b0}},n_fcs[31:24]};
              axis_fifo.tstrb  <= 16'h0000;
              axis_fifo.tlast  <= 1'b1;
            end
            default: begin
              axis_fifo.tvalid <= 1'b0;
              axis_fifo.tdata  <= 128'b0;
              axis_fifo.tstrb  <= 16'b0;
              axis_fifo.tlast  <= 1'b0;
            end
          endcase 
        end
        default: begin //Not data received
          axis_fifo.tvalid <= 1'b0;
          axis_fifo.tdata  <= 128'b0;
          axis_fifo.tstrb  <= 16'b0;
          axis_fifo.tlast  <= 1'b0;          
        end
      endcase 
    end
  end

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
  wire          eof, next_eof;




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
    .RST_N(RST_N),
    .NEXT_EOF(next_eof),
    .EOF(eof),
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
    .NEXT_EOF(next_eof), // The next valid transfer will complete the current packet
    .EOF(eof)            // This transfer completes the current packet
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