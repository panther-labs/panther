region = us-west-2
bucket = panther-public-cloudformation-templates

upload-all:
	for template in `find . -iname 'panther-*.yml'`; do \
		$(MAKE) upload-single template=$$(basename $$template) | grep 'upload'; \
	done

upload-single:
	version=`egrep 'Version: v' $(template)  | tr -s ' ' | cut -d ' ' -f 3`; \
	templateDisplayName=`echo $(template) | cut -d'.' -f1`; \
	if [[ $$version != "" ]]; then \
		aws s3 cp $(template) s3://$(bucket)/$$templateDisplayName/$$version/template.yml --acl public-read; \
	fi; \
	aws s3 cp $(template) s3://$(bucket)/$$templateDisplayName/latest/template.yml --acl public-read; \

