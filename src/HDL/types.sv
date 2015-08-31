package definitions;

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


`define AXI4_STREAM_STRUCT(NAME) \
   axi_stream_``NAME``

`define AXI4_STREAM_STRUCT_DEF(NAME, DATA_WIDTH) \
 typedef struct { \
        logic tvalid; \
        logic tready; \
        logic [DATA_WIDTH/8-1:0] tstrb;   \
        logic [DATA_WIDTH-1:0]   tdata;   \
    } `AXI4_STREAM_STRUCT(NAME);


endpackage