//======================================================================
//
// AES_rounds.v
// ------------
//
// AES rounds on 128 bit plaintext for 128 bit key . 
//
//======================================================================

module AES_rounds (
							input  					clk, 
							input  					rst,
							input  					start,					
							input  		[127:0] 	plaintext,
							input  					pause,
							input  		[127:0] 	key_1,
							input  		[127:0] 	key_2,
							input  		[127:0] 	key_3,
							input  		[127:0] 	key_4,
							input  		[127:0] 	key_5,
							input  		[127:0] 	key_6,
							input  		[127:0] 	key_7,
							input  		[127:0] 	key_8,
							input  		[127:0] 	key_9,
							input  		[127:0] 	key_10,
							input  		[127:0] 	key_11,
							output reg 	[127:0] 	data_out,
							output reg 				ready									
							);

  //----------------------------------------------------------------
  // Internal parameter definitions.
  //----------------------------------------------------------------							
  parameter  DEBUG     		= 0;
  localparam IDLE   		= 4'h0; 
  localparam INITIAL_ROUND  = 4'h1;
  localparam REPEAT_ROUND   = 4'h2;
  localparam FINAL_ROUND    = 4'h3;
  localparam AES128_ROUNDS  = 4'h9;

  //----------------------------------------------------------------
  // Shift rows function for 128 bit state
  //----------------------------------------------------------------
  function [127:0] shift_rows (input [127:0] data_in);
	reg [31:0] word0,word1,word2,word3;
	reg [31:0] word_shift0,word_shift1,word_shift2,word_shift3;
    begin
      word0 = data_in[127 : 096];
      word1 = data_in[095 : 064];
      word2 = data_in[063 : 032];
      word3 = data_in[031 : 000];
      word_shift0 = {word0[31 : 24], word1[23 : 16], word2[15 : 08], word3[07 : 00]};
      word_shift1 = {word1[31 : 24], word2[23 : 16], word3[15 : 08], word0[07 : 00]};
      word_shift2 = {word2[31 : 24], word3[23 : 16], word0[15 : 08], word1[07 : 00]};
      word_shift3 = {word3[31 : 24], word0[23 : 16], word1[15 : 08], word2[07 : 00]};
      shift_rows = {word_shift0, word_shift1, word_shift2, word_shift3};
    end
  endfunction // shift_rows

  //----------------------------------------------------------------
  // Mix word function for 128 bit state
  //----------------------------------------------------------------
  function [31 : 0] mix_word(input  [31 : 0] word_in);
    reg [7 : 0] byte0, byte1, byte2, byte3;
    reg [7 : 0] mixed_byte0, mixed_byte1, mixed_byte2, mixed_byte3;
    begin
      byte0 = word_in[31 : 24];
      byte1 = word_in[23 : 16];
      byte2 = word_in[15 : 08];
      byte3 = word_in[07 : 00];
      mixed_byte0 = Mul_2(byte0) ^ Mul_3(byte1) 	^ byte2    		^ byte3;
      mixed_byte1 = byte0    	 ^ Mul_2(byte1) 	^ Mul_3(byte2) 	^ byte3;
      mixed_byte2 = byte0    	 ^ byte1    		^ Mul_2(byte2) 	^ Mul_3(byte3);
      mixed_byte3 = Mul_3(byte0) ^ byte1    		^ byte2    		^ Mul_2(byte3);
      mix_word = {mixed_byte0, mixed_byte1, mixed_byte2, mixed_byte3};
    end
  endfunction // mix_word
  
  //----------------------------------------------------------------
  // Mix columns function for 128 bit state
  //----------------------------------------------------------------
  function [127 : 0] mix_columns (input [127 : 0]  data_in); 
  	reg [31:0] word0,word1,word2,word3;
	reg [31:0] word_shift0,word_shift1,word_shift2,word_shift3;
    begin
      word0 = data_in[127 : 096];
      word1 = data_in[095 : 064];
      word2 = data_in[063 : 032];
      word3 = data_in[031 : 000];
      word_shift0 = mix_word (word0);
	  word_shift1 = mix_word (word1);
	  word_shift2 = mix_word (word2);
	  word_shift3 = mix_word (word3);
      mix_columns = {word_shift0, word_shift1, word_shift2, word_shift3};
    end
  endfunction // mix_columns
  
  //----------------------------------------------------------------
  // Galois field multiplication by 2 function
  //----------------------------------------------------------------
  function [7 : 0] Mul_2(input [7 : 0] Din);
    begin	Mul_2 = {Din[6 : 0], 1'b0} ^ (8'h1b & {8{Din[7]}}); end
  endfunction // // Mul_3

  //----------------------------------------------------------------
  // Galois field multiplication by 3 function
  //----------------------------------------------------------------
  function [7 : 0] Mul_3(input [7 : 0] Din);
    begin      Mul_3 = Mul_2(Din) ^ Din;    end
  endfunction // Mul_3
  
  //----------------------------------------------------------------
  // Registers declarations.
  //----------------------------------------------------------------  
  reg  [3:0]   state_count;
  reg  [3:0]   state_machine;
  reg  [127:0] state_round;
  reg  [127:0] state_round_old;
  wire [127:0] state_round_new;
  wire         start_re;			
  //----------------------------------------------------------------
  // AES_rounds_state_machine
  //
  // state machine for aes key expansion. This FSM stores previous 
  // value & uses it for next 32 bit block of key. Repeats this 
  // process for 10 rounds for AES 128 bit key expansion
  //----------------------------------------------------------------
  always@(posedge clk or posedge rst)
	begin : AES_rounds_state_machine
		if(rst)
			begin
				ready = 0; 			
				state_count = 'b0;
				state_round_old = 'b0;
				state_machine = IDLE;				
			end
		else
			begin
				if (!pause)
					begin
							case (state_machine)
								IDLE : 
												if (start_re)
													begin	
														ready = 0;
														state_count = 'b0;
														state_machine = INITIAL_ROUND;
													end
												else 
														state_machine = IDLE;
												
								INITIAL_ROUND:
												if (start_re)
														state_machine = IDLE;												
												else 
													begin
														state_machine = REPEAT_ROUND;
														state_round_old = key_1 ^ plaintext;	
														if (DEBUG == 1) $display("\n\nKeyAddition     = 0x%032x\n\n", state_round_old);
													end
								REPEAT_ROUND :
												if (start_re)
														state_machine = IDLE;												
												else 
													begin
														state_count = (state_count +  1);
														if (state_count == AES128_ROUNDS)
															begin
																ready = 1;
																state_machine = FINAL_ROUND;
															end
														else 
																state_machine = REPEAT_ROUND;
															
														state_round_old = state_round;
														if (DEBUG == 1) $display("\n........ROUNDS     = %d", state_count);
													end
										
								FINAL_ROUND:		begin
														ready = 1;
														state_machine = IDLE;
													end
								default :
												begin 
												end
							endcase
						
					end
			end								
	end // AES_rounds_state_machine
	
  //----------------------------------------------------------------
  // AES_rounds_state_count
  //
  // state machine for aes key expansion. This FSM stores previous 
  // value & uses it for next 32 bit block of key. Repeats this 
  // process for 10 rounds for AES 128 bit key expansion
  //----------------------------------------------------------------
  always@(*)
	begin : AES_rounds_state_count
		if(rst)
			begin
				state_round = 'b0; 
				data_out = 'b0;	
			end
		else
			begin
				case(state_count)
					4'h0 :  begin 
								state_round  = (mix_columns(shift_rows(state_round_new)) ^ key_2); 
								if (DEBUG == 1) $display("ROUND : 1    Substitution =0x%032x,  ShiftRow =0x%032x, MixColumn ==0x%032x, KeyAddition ==0x%032x ", 
										state_round_new, shift_rows(state_round_new) , mix_columns(shift_rows(state_round_new)) ,state_round ); 
							end
							
					4'h1 :  begin 
								state_round  = (mix_columns(shift_rows(state_round_new)) ^ key_3); 
								if (DEBUG == 1) $display("ROUND : 2    Substitution =0x%032x,  ShiftRow =0x%032x, MixColumn ==0x%032x, KeyAddition ==0x%032x ", 
										state_round_new, shift_rows(state_round_new) , mix_columns(shift_rows(state_round_new)) ,state_round );
							end
					4'h2 :  begin 
								state_round  = (mix_columns(shift_rows(state_round_new)) ^ key_4); 
								if (DEBUG == 1) $display("ROUND : 3    Substitution =0x%032x,  ShiftRow =0x%032x, MixColumn ==0x%032x, KeyAddition ==0x%032x ", 
										state_round_new, shift_rows(state_round_new) , mix_columns(shift_rows(state_round_new)) ,state_round );
							end								
					4'h3 :  begin 
								state_round  = (mix_columns(shift_rows(state_round_new)) ^ key_5); 
								if (DEBUG == 1) $display("ROUND : 4    Substitution =0x%032x,  ShiftRow =0x%032x, MixColumn ==0x%032x, KeyAddition ==0x%032x ", 
										state_round_new, shift_rows(state_round_new) , mix_columns(shift_rows(state_round_new)) ,state_round );
							end								
								
					4'h4 :  begin 
								state_round  = (mix_columns(shift_rows(state_round_new)) ^ key_6); 
								if (DEBUG == 1) $display("ROUND : 5    Substitution =0x%032x,  ShiftRow =0x%032x, MixColumn ==0x%032x, KeyAddition ==0x%032x ", 
										state_round_new, shift_rows(state_round_new) , mix_columns(shift_rows(state_round_new)) ,state_round );
							end								
								
					4'h5 :  begin 
								state_round  = (mix_columns(shift_rows(state_round_new)) ^ key_7); 
								if (DEBUG == 1) $display("ROUND : 6    Substitution =0x%032x,  ShiftRow =0x%032x, MixColumn ==0x%032x, KeyAddition ==0x%032x ", 
										state_round_new, shift_rows(state_round_new) , mix_columns(shift_rows(state_round_new)) ,state_round );
							end								
								
					4'h6 :  begin 
								state_round  = (mix_columns(shift_rows(state_round_new)) ^ key_8); 
								if (DEBUG == 1) $display("ROUND : 7    Substitution =0x%032x,  ShiftRow =0x%032x, MixColumn ==0x%032x, KeyAddition ==0x%032x ", 
										state_round_new, shift_rows(state_round_new) , mix_columns(shift_rows(state_round_new)) ,state_round );
							end								
								
					4'h7 :  begin 
								state_round  = (mix_columns(shift_rows(state_round_new)) ^ key_9); 
								if (DEBUG == 1) $display("ROUND : 8    Substitution =0x%032x,  ShiftRow =0x%032x, MixColumn ==0x%032x, KeyAddition ==0x%032x ", 
										state_round_new, shift_rows(state_round_new) , mix_columns(shift_rows(state_round_new)) ,state_round );
							end								
								
					4'h8 :  begin 
								state_round  = (mix_columns(shift_rows(state_round_new)) ^ key_10); 
								if (DEBUG == 1) $display("ROUND : 9    Substitution =0x%032x,  ShiftRow =0x%032x, MixColumn ==0x%032x, KeyAddition ==0x%032x ", 
										state_round_new, shift_rows(state_round_new) , mix_columns(shift_rows(state_round_new)) ,state_round );
							end								
								
					4'h9 :  begin 
								state_round  = (mix_columns(shift_rows(state_round_new)) ^ key_11);
								data_out     = ((shift_rows(state_round_new)) ^ key_11);
								if (DEBUG == 1) $display("ROUND : 10    Substitution =0x%032x,  ShiftRow =0x%032x, MixColumn ==0x%032x, KeyAddition ==0x%032x ", 
										state_round_new, shift_rows(state_round_new) , mix_columns(shift_rows(state_round_new)) ,state_round );
							end								
								
					4'ha :  begin 
								state_round  = (mix_columns(shift_rows(state_round_new)) ); 
								if (DEBUG == 1) $display("ROUND : 11    Substitution =0x%032x,  ShiftRow =0x%032x, MixColumn ==0x%032x, KeyAddition ==0x%032x ", 
										state_round_new, shift_rows(state_round_new) , mix_columns(shift_rows(state_round_new)) ,state_round );
							end								
								
					default : 
						begin
								data_out     = 'b0;
						end
				endcase
			end
	end  // AES_rounds_state_count

  //----------------------------------------------------------------
  // sbox instantiations for parallel 128 bit substitution  
  //----------------------------------------------------------------
  AES_sbox SB5 (state_round_old[127:120],state_round_new[127:120]);
  AES_sbox SB6 (state_round_old[119:112],state_round_new[119:112]);
  AES_sbox SB7 (state_round_old[111:104],state_round_new[111:104]);
  AES_sbox SB8 (state_round_old[103:096],state_round_new[103:096]);

  AES_sbox SB9  (state_round_old[095:088],state_round_new[095:088]);
  AES_sbox SB10 (state_round_old[087:080],state_round_new[087:080]);
  AES_sbox SB11 (state_round_old[079:072],state_round_new[079:072]);
  AES_sbox SB12 (state_round_old[071:064],state_round_new[071:064]);

  AES_sbox SB13 (state_round_old[063:056],state_round_new[063:056]);
  AES_sbox SB14 (state_round_old[055:048],state_round_new[055:048]);
  AES_sbox SB15 (state_round_old[047:040],state_round_new[047:040]);
  AES_sbox SB16 (state_round_old[039:032],state_round_new[039:032]);

  AES_sbox SB17 (state_round_old[031:024],state_round_new[031:024]);
  AES_sbox SB18 (state_round_old[023:016],state_round_new[023:016]);
  AES_sbox SB19 (state_round_old[015:008],state_round_new[015:008]);
  AES_sbox SB20 (state_round_old[007:000],state_round_new[007:000]);

  rising_edge 		U2 (clk, rst,start,start_re);	  
  
endmodule // AES_rounds

//======================================================================
// EOF AES_rounds.v
//======================================================================