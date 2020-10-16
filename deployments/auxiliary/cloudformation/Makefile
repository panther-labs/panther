region = us-west-2
bucket = panther-public-cloudformation-templates

upload-all:
	for template in `find . -iname 'panther-*.yml'`; do \
		$(MAKE) upload-single template=$$(basename $$template) | grep 'upload'; \
	done

upload-single:
	version=`cat ../../../VERSION | xargs`; \
	templateDisplayName=`echo $(template) | cut -d'.' -f1`; \
	aws s3 cp $(template) s3://$(bucket)/$$templateDisplayName/v$$version/template.yml --acl public-read;
	aws s3 cp $(template) s3://$(bucket)/$$templateDisplayName/latest/template.yml --acl public-read;
