package io.netty.gradle.plugins.dockerbuild;

import java.util.List;

public class DockerBuildExtension {

    /**
     * The base image to use when building docker images.
     */
    private String baseImage;

    /**
     * Commands to be run during docker image build.
     */
    private List<String> runCommands;

    /**
     * Script to be set as the default command.
     */
    private String script;

    public String getBaseImage() {
        return baseImage;
    }

    public void setBaseImage(String baseImage) {
        this.baseImage = baseImage;
    }

    public List<String> getRunCommands() {
        return runCommands;
    }

    public void setRunCommands(List<String> runCommands) {
        this.runCommands = runCommands;
    }

    public String getScript() {
        return script;
    }

    public void setScript(String script) {
        this.script = script;
    }
}
