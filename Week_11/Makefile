TAMARIN = tamarin-prover --prove
SEPARATOR = ==============================================================================

model = Mastercard-solution.spthy
output = $(subst .spthy,.proof,$(model))

prove:
ifndef model
	@echo You must define "model"
else
	@echo Started analysis...
	@($(TAMARIN) $(model) --output=$(output)) > a.tmp 2>&1
	
	@#add breaklines
	@echo >> $(output)
	@echo >> $(output)
	
	@#add results to proof file
	@(sed -n '/^$(SEPARATOR)/,$$p' a.tmp) >> $(output)
	
	@#Clean up
	@$(RM) a.tmp
	@echo Done.
endif

.PHONY: clean

clean:
	$(RM) *.tmp #*.proof
