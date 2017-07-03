//======================================================================
//
// AES_key_expansion.v
// ------------------
//
// AES key schedule for 128 bit key. 
//
//======================================================================

module AES_key_expansion (
							input  				clk, 
							input  				rst,
							input  				start,
							input  	   [127:0] 	key,
							input  				pause,
							output reg 			ready,							
							output  [127:0] 	key_1,
							output  [127:0] 	key_2,
							output  [127:0] 	key_3,
							output  [127:0] 	key_4,
							output  [127:0] 	key_5,
							output  [127:0] 	key_6,
							output  [127:0] 	key_7,
							output  [127:0] 	key_8,
							output  [127:0] 	key_9,
							output  [127:0] 	key_10,
							output  [127:0] 	key_11							
						 );

  //----------------------------------------------------------------
  // Internal parameter definitions.
  //----------------------------------------------------------------
  localparam IDLE   		= 4'h0;
  localparam START  		= 4'h1;
  localparam END    		= 4'h2;
  localparam AES128_ROUNDS  = 4'hB;

  //----------------------------------------------------------------
  // Registers declarations.
  //----------------------------------------------------------------
  reg  [3:0]   key_round_count;
  reg  [3:0]   state_machine;
  reg  [127:0] key_round_old;
  wire [127:0] key_round_new;  
  wire [127:0] key_round;
  wire         start_re;
  
  //----------------------------------------------------------------
  // Output port signal assignments.
  //----------------------------------------------------------------
  assign key_1  = (rst) ? 'b0 : (key_round_count ==0)  ?  key 		: key_1; 
  assign key_2  = (rst) ? 'b0 : (key_round_count ==1)  ?  key_round : key_2;
  assign key_3  = (rst) ? 'b0 : (key_round_count ==2)  ?  key_round : key_3;
  assign key_4  = (rst) ? 'b0 : (key_round_count ==3)  ?  key_round : key_4;
  assign key_5  = (rst) ? 'b0 : (key_round_count ==4)  ?  key_round : key_5;
  assign key_6  = (rst) ? 'b0 : (key_round_count ==5)  ?  key_round : key_6;
  assign key_7  = (rst) ? 'b0 : (key_round_count ==6)  ?  key_round : key_7;
  assign key_8  = (rst) ? 'b0 : (key_round_count ==7)  ?  key_round : key_8;
  assign key_9  = (rst) ? 'b0 : (key_round_count ==8)  ?  key_round : key_9;
  assign key_10 = (rst) ? 'b0 : (key_round_count ==9)  ?  key_round : key_10;
  assign key_11 = (rst) ? 'b0 : (key_round_count ==10) ?  key_round : key_11;
  
  assign key_round_new = (rst) ? 'b0 : (key_round_count ==0) ?  key : key_round;
  
  //----------------------------------------------------------------
  // AES_key_expansion_state_machine
  //
  // state machine for aes key expansion. This FSM stores previous 
  // value & uses it for next 32 bit block of key. Repeats this 
  // process for 10 rounds for AES 128 bit key expansion
  //----------------------------------------------------------------
  always@(posedge clk or posedge rst)
	begin : AES_key_expansion_state_machine
		if(rst)
			begin 
				key_round_count = 'b0;
				key_round_old 	= 'b0;
				ready 			= 'b0; 
				state_machine 	= IDLE;				
			end
		else
			begin
				if (!pause)
					begin
							case (state_machine)
								IDLE : 
										if (start)
											begin	
												ready = 0;
												key_round_count = 'b0;												
												state_machine = START;												
											end
										else 
											state_machine = IDLE;
								START:
										begin
											key_round_count = key_round_count +  1;
											if (start_re)
												state_machine = IDLE;											
											else 
												begin
													if (key_round_count == AES128_ROUNDS)
														begin
															ready = 1;
															state_machine = END;													
														end
													else 
														state_machine = START;
												end
										end										
								END:	
										if (~start)
											begin
												ready = 1;
												state_machine = IDLE;											
											end
										
								default :begin 
										 end
							endcase
							
						key_round_old = key_round_new;
				end
			end								
	end	// AES_key_expansion_state_machine

  //----------------------------------------------------------------
  // key_round_assign
  //
  // counter to assign expanded aes keys expansion.
  // 
  //----------------------------------------------------------------	
    /*//always@(posedge clk or posedge rst)
    always@(*)
	begin : key_round_assign
		if(rst)
			begin
				key_round_new = 'b0; 		
			end
		else
			begin
			key_round_new = (key_round_count == 0) ?  key : key_round;
			
				case(key_round_count)
					4'h0 :  begin key_round_new = key; 		 end
					4'h1 :  begin key_round_new = key_round;   end
					4'h2 :  begin key_round_new = key_round;   end
					4'h3 :  begin key_round_new = key_round;   end
					4'h4 :  begin key_round_new = key_round;   end
					4'h5 :  begin key_round_new = key_round;   end
					4'h6 :  begin key_round_new = key_round;   end
					4'h7 :  begin key_round_new = key_round;   end
					4'h8 :  begin key_round_new = key_round;   end
					4'h9 :  begin key_round_new = key_round;   end		
					4'ha :  begin key_round_new = key_round;   end	
					4'hb :  begin end
					default : begin end
				endcase 
			end
	end	// key_round_assign */

  //----------------------------------------------------------------
  // sbox instantiations for parallel 32 bit substitution  
  //----------------------------------------------------------------
  AES_key_schedule KS1 (key_round_old,key_round_count,key_round);		
  rising_edge 		U1 (clk, rst,start,start_re);	
  
  endmodule // AES_key_expansion
  
//======================================================================
// EOF AES_key_expansion.v
//======================================================================