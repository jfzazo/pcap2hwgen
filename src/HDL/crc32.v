
// x^32 + x^26 + x^23 + x^22 + x^16 + x^12 + x^11 + x^10 + x^8 + x^7 + x^5 + x^4 + x^2 + x + 1
function [31:0] crc_serial;
  input [31:0] crc;
  input        data;
begin
  crc_serial[0] = crc[1];
  crc_serial[1] = crc[2];
  crc_serial[2] = crc[3];
  crc_serial[3] = crc[4];
  crc_serial[4] = crc[5];
  crc_serial[5] = crc[0] ^ crc[6] ^ data;
  crc_serial[6] = crc[7];
  crc_serial[7] = crc[8];
  crc_serial[8] = crc[0] ^ crc[9] ^ data;
  crc_serial[9] = crc[0] ^ crc[10] ^ data;
  crc_serial[10] = crc[11];
  crc_serial[11] = crc[12];
  crc_serial[12] = crc[13];
  crc_serial[13] = crc[14];
  crc_serial[14] = crc[15];
  crc_serial[15] = crc[0] ^ crc[16] ^ data;
  crc_serial[16] = crc[17];
  crc_serial[17] = crc[18];
  crc_serial[18] = crc[19];
  crc_serial[19] = crc[0] ^ crc[20] ^ data;
  crc_serial[20] = crc[0] ^ crc[21] ^ data;
  crc_serial[21] = crc[0] ^ crc[22] ^ data;
  crc_serial[22] = crc[23];
  crc_serial[23] = crc[0] ^ crc[24] ^ data;
  crc_serial[24] = crc[0] ^ crc[25] ^ data;
  crc_serial[25] = crc[26];
  crc_serial[26] = crc[0] ^ crc[27] ^ data;
  crc_serial[27] = crc[0] ^ crc[28] ^ data;
  crc_serial[28] = crc[29];
  crc_serial[29] = crc[0] ^ crc[30] ^ data;
  crc_serial[30] = crc[0] ^ crc[31] ^ data;
  crc_serial[31] = crc[0] ^ data;
end
endfunction

function [31:0] crc_iteration;
  input [7:0] iters;
  input [31:0] crc;
  input [127:0] data;
  integer i;
begin
  crc_iteration = crc;
  for(i=0;i<iters;i=i+1) begin
    crc_iteration = crc_serial(crc_iteration, data[i]);
  end

end
endfunction