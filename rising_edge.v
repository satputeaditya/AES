// rising_edge.v

  //-------------------------------------------
  // rising edge detect function
  //-------------------------------------------
    module rising_edge(
						input clk,
						input rst,
						input signal_in,
						output signal_out
					);	
    reg signal;					
	assign signal_out = signal_in & (~ signal);

	always@(posedge clk or posedge rst)
		begin  
				if(rst)
					signal <= 'b0; 			
				else
					signal <= signal_in;			
		end
	endmodule