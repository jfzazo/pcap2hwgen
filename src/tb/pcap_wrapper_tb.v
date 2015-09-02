`timescale 1ns / 1ps
`define NULL 0

//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date: 01/22/2015 02:49:20 PM
// Design Name: 
// Module Name: pcap_wrapper_tb
// Project Name: 
// Target Devices: 
// Tool Versions: 
// Description: 
// 
// Dependencies: 
// 
// Revision:
// Revision 0.01 - File Created
// Additional Comments:
// 
//////////////////////////////////////////////////////////////////////////////////


module pcap_wrapper_tb  #(
    parameter pcap_filename = "/home/jf.zazo/Desktop/FPGA/detectpro_isa/driver/user/Trazas/2flujos_crc"
)(
);

reg clk;
reg rst_n;


reg [127 : 0] pcap_tdata;
reg           pcap_tvalid;
wire          pcap_tready;

reg           pcap_finished;

integer file = 0;
integer dump_file = 0;

always  
   #5  clk =  !clk;

initial begin
   clk       = 0;
   rst_n     = 0;
   pcap_finished = 0;
   pcap_tvalid = 0;
   pcap_tdata = 0;
   #20;
   rst_n = 1;
   #15
   
   //open  file
   if (pcap_filename == "none") begin
       $display("Memory filename parameter not set");
       $finish; 
   end

   file = $fopen(pcap_filename, "rb");
   if (file == `NULL) begin
       $display("can't read memory input %s", pcap_filename);
       $finish;
   end
   
   $display("MEMORY: %m reading from %s", pcap_filename);


    while(!$feof(file)) begin
        #5
        pcap_tvalid = 1;

        pcap_tdata[0*8+:8] <= $fgetc(file);    
        pcap_tdata[1*8+:8] <= $fgetc(file);
        pcap_tdata[2*8+:8] <= $fgetc(file);
        pcap_tdata[3*8+:8] <= $fgetc(file);
        pcap_tdata[4*8+:8] <= $fgetc(file);
        pcap_tdata[5*8+:8] <= $fgetc(file);
        pcap_tdata[6*8+:8] <= $fgetc(file);
        pcap_tdata[7*8+:8] <= $fgetc(file);
        pcap_tdata[8*8+:8] <= $fgetc(file);
        pcap_tdata[9*8+:8] <= $fgetc(file);
        pcap_tdata[10*8+:8] <= $fgetc(file);
        pcap_tdata[11*8+:8] <= $fgetc(file);
        pcap_tdata[12*8+:8] <= $fgetc(file);
        pcap_tdata[13*8+:8] <= $fgetc(file);
        pcap_tdata[14*8+:8] <= $fgetc(file);
        pcap_tdata[15*8+:8] <= $fgetc(file);
        #5
        pcap_tvalid = 1;
//        @(posedge pcap_tready)
    end   
   
   
   #15
   pcap_finished = 1'b1;
 
    
end


initial begin
    @(posedge pcap_finished)  
        #1000
    $fclose(dump_file);
    $fclose(file);
    $finish;
end   



pcap2hwgen pcap2hwgen_i ( 
  .CLK(clk),
  .RST_N(rst_n),
  .PCAP_TVALID(pcap_tvalid),
  .PCAP_TREADY(pcap_tready),
  .PCAP_TDATA(pcap_tdata),
  .HWGEN_TVALID(),
  .HWGEN_TREADY(1'b1),
  .HWGEN_TDATA()
);

    
endmodule
