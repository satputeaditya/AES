//======================================================================
//
// AES_key_schedule.v
// ------------------
//
// AES key schedule for 128 bit key. 
//
//======================================================================

module AES_key_schedule (
							input  [127:0] 	data_in,
							input  [3:0] 	round,					
							output [127:0] 	data_out
						 );
						 
  //----------------------------------------------------------------
  // Registers including update variables and write enable.
  //----------------------------------------------------------------			   
  wire [127:0] Key_rotated;
  wire [31:0]  Key_substituted;
  wire [31:0]  Key_Column;  

  //----------------------------------------------------------------
  // Rotate function
  //----------------------------------------------------------------
  function [127 : 0] rotate_word_128(input [127 : 0] Din);
    begin	
		rotate_word_128 =
						{
							Din[127:120],	Din[119:112],	Din[111:104],   Din[103:096],		// Words 16  15  14  13  
							Din[095:088],	Din[087:080],	Din[079:072],	Din[071:064],		// Words 12  11  10  09
							Din[063:056],	Din[055:048],	Din[047:040],	Din[039:032],		// Words 08  07  06  05 
							Din[023:016],   Din[015:008],	Din[007:000],	Din[031:024]		// Words 03  02  01  04
						};
	end
	endfunction 
	
  //--------------------------------------------------------------------------------
  // Rcon function pre-computed values to allow rcon for AES 128 bit & 256 bit keys
  //--------------------------------------------------------------------------------
  function [31 : 0] rcon(input [3 : 0] round);
    begin	
      case (round)
         4'h0 	:  rcon = 32'h8D_000000;   
         4'h1 	:  rcon = 32'h01_000000;
         4'h2 	:  rcon = 32'h02_000000;
         4'h3 	:  rcon = 32'h04_000000;
         4'h4 	:  rcon = 32'h08_000000;
         4'h5 	:  rcon = 32'h10_000000;
         4'h6 	:  rcon = 32'h20_000000;
         4'h7 	:  rcon = 32'h40_000000;
         4'h8 	:  rcon = 32'h80_000000;
         4'h9 	:  rcon = 32'h1B_000000;
         4'hA 	:  rcon = 32'h36_000000;
         4'hB 	:  rcon = 32'h6C_000000;
         4'hC 	:  rcon = 32'hD8_000000;
         4'hD 	:  rcon = 32'hAB_000000;
         4'hE 	:  rcon = 32'h4D_000000;
         4'hF 	:  rcon = 32'h9A_000000;
         default:  rcon = 32'h00_000000;
      endcase
	end
  endfunction

  //----------------------------------------------------------------
  // Concurrent connectivity for ports etc.
  //----------------------------------------------------------------
  assign Key_rotated = rotate_word_128(data_in);
  assign Key_Column  = Key_substituted ^ data_in[127:96] ^ rcon(round);
  assign data_out    = {Key_Column,
					   (Key_Column^data_in[95: 64]),
					   (Key_Column^data_in[95: 64]^data_in[63: 32]),
					   (Key_Column^data_in[95: 64]^data_in[63: 32]^data_in[31: 0])};

																	
  //----------------------------------------------------------------
  // sbox instantiations for parallel 32 bit substitution  
  //----------------------------------------------------------------
   AES_sbox SB1 ( Key_rotated[031:024], Key_substituted[031:024] );
   AES_sbox SB2 ( Key_rotated[023:016], Key_substituted[023:016] );
   AES_sbox SB3 ( Key_rotated[015:008], Key_substituted[015:008] );
   AES_sbox SB4 ( Key_rotated[007:000], Key_substituted[007:000] ); 
	
endmodule // AES_key_schedule

//======================================================================
// EOF AES_key_schedule.v
//======================================================================