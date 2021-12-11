#!/usr/bin/bash
# Executing the fix only if fid is installed
if [ -e /opt/radiantone/vds/vds_server/conf/cloud.properties ] ; then
        if [[ -z "${RLI_HOME}" ]]; then
                echo "RLI_HOME IS NOT DEFINED"
                exit 0
        fi
        # Installing zip
        yum install -y zip
        mkdir -p "$RLI_HOME/backup"
        IFS=$'\n'
        for i in $(find $RLI_HOME -iname "log4j-core-*.jar" -not -path "$RLI_HOME/backup/*");
        do
          $RLI_HOME/jdk/bin/jar tf $i | grep -i "org/apache/logging/log4j/core/lookup/JndiLookup.class"
          if [ $? -eq 0 ]; then
            echo "$i contains vulnerability"
            echo "Patching $i"; cp "$i" "$RLI_HOME/backup"; zip -q -d "$i" org/apache/logging/log4j/core/lookup/JndiLookup.class;
          else
            echo "$i has been already been patched and is safe"
          fi
        done
        unset IFS

        #For Versions 7.3.17 and above, the following extra step is required:
        echo "Deleting the folder $RLI_HOME/vds_server/work/docs"
        rm -rf $RLI_HOME/vds_server/work/docs
        echo "Moving the file $RLI_HOME/apps/web/docs.war to $RLI_HOME/vds/apps/web/disabled"
        mv -f $RLI_HOME/apps/web/docs.war $RLI_HOME/apps/web/disabled
else
        echo "FID is not installed, skipping the fix"
fi
