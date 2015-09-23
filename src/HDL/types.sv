package definitions;


parameter  PCAP_US_RESOLUTION_C = 32'hA1B2C3D4;
parameter  PCAP_NS_RESOLUTION_C = 32'hA1B23C4D;
parameter  HWGEN_MAGIC_NUMBER_C = 16'h6969;
parameter  CLOCK_FREQ_HZ        = 156250000;
parameter  NS_PER_CYCLE         = (1.0/CLOCK_FREQ_HZ*1000000000);
parameter  NS_PER_CYCLE_INV_x1e5=  CLOCK_FREQ_HZ/10000; // (1.0/(1.0/CLOCK_FREQ_HZ*1000000000)) = 0.15625;



/**
* @brief Global pcap header.
*/
typedef struct{
  logic [31:0] magic_number;   /**< magic number */
  logic [15:0] version_major;  /**< major version number */
  logic [15:0] version_minor;  /**< minor version number */
  logic [31:0] thiszone;       /**< GMT to local correction */
  logic [31:0] sigfigs;        /**< accuracy of timestamps */
  logic [31:0] snaplen;        /**< max length of captured packets, in octets */
  logic [31:0] network;        /**< data link type */
} pcap_hdr_t;

/**
* @brief Pcap packet header.
*/
typedef struct{
  logic [31:0] ts_sec;         /**< timestamp seconds */
  logic [31:0] ts_usec;        /**< timestamp microseconds */
  logic [31:0] incl_len;       /**< number of octets of packet saved in file */
  logic [31:0] orig_len;       /**< actual length of packet */
} pcaprec_hdr_t;


typedef struct{
  logic [63:0] ts;         /**< timestamp nanoseconds */
  logic [31:0] incl_len;       /**< number of octets of packet saved in file */
  logic [31:0] orig_len;       /**< actual length of packet */
  logic        valid;          /**< The previous content is valid */
} genericrec_hdr_t;



typedef struct{
  logic [16:0] magic_number;
  logic [16:0] orig_len;
  logic [31:0] ifg;     
} hwgen_hdr_t;


`define AXI4_STREAM_STRUCT(NAME) \
   axi_stream_``NAME``

`define AXI4_STREAM_STRUCT_DEF(NAME, DATA_WIDTH) \
 typedef struct { \
        logic tvalid; \
        logic tlast; \
        logic [DATA_WIDTH/8-1:0] tstrb;   \
        logic [DATA_WIDTH-1:0]   tdata;   \
    } `AXI4_STREAM_STRUCT(NAME);



`define AXI4_STREAM_READY_STRUCT(NAME) \
   axi_stream_ready_``NAME``

`define AXI4_STREAM_READY_STRUCT_DEF(NAME, DATA_WIDTH) \
 typedef struct { \
        logic tready; \
    } `AXI4_STREAM_READY_STRUCT(NAME);

`define sizeof(OBJECT) $bits(OBJECT)

endpackage